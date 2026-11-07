//! Linux file watching through one non-blocking inotify descriptor. The
//! descriptor is polled together with [`Stop`]'s cancellation pipe, so quiet
//! files sleep in the kernel and never require a timer-driven stat loop.
//!
//! This is a Rust-only Linux implementation preserving the API and behavior
//! of `internal/fswait/fswait_other.go` and `internal/fswait/watch_other.go`.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{File, Stop, changed};

const MASK: u32 = libc::IN_MODIFY
    | libc::IN_CLOSE_WRITE
    | libc::IN_ATTRIB
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO;

#[derive(Clone, Debug)]
enum Node {
    Exact(PathBuf),
    Parent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddResult {
    Added,
    Already,
    Missing,
    Failed,
}

pub(crate) struct Inner {
    fd: Option<OwnedFd>,
    wake_r: Option<OwnedFd>,
    wake_w: Option<OwnedFd>,
    closed: bool,
    registration_failed: bool,
    desired: HashSet<PathBuf>,
    missing: HashSet<PathBuf>,
    nodes: HashMap<PathBuf, RawFd>,
    by_fd: HashMap<RawFd, Node>,
    fresh: HashSet<PathBuf>,
    dirty: bool,
    #[cfg(test)]
    add_watch_errno: Option<i32>,
}

impl Inner {
    fn new() -> Inner {
        let (wake_r, wake_w) = match wake_pipe() {
            Some((r, w)) => (Some(r), Some(w)),
            None => (None, None),
        };
        let fd = inotify();
        Inner {
            registration_failed: fd.is_none(),
            fd,
            wake_r,
            wake_w,
            closed: false,
            desired: HashSet::new(),
            missing: HashSet::new(),
            nodes: HashMap::new(),
            by_fd: HashMap::new(),
            fresh: HashSet::new(),
            dirty: true,
            #[cfg(test)]
            add_watch_errno: None,
        }
    }

    fn remove_nodes(&mut self) {
        if let Some(fd) = &self.fd {
            for &wd in self.nodes.values() {
                // SAFETY: wd belongs to this inotify instance. The kernel
                // queues IN_IGNORED; stale events are ignored later.
                unsafe { libc::inotify_rm_watch(fd.as_raw_fd(), wd) };
            }
        }
        self.nodes.clear();
        self.by_fd.clear();
    }

    fn remove_path(&mut self, path: &Path) {
        let Some(wd) = self.nodes.remove(path) else {
            return;
        };
        self.by_fd.remove(&wd);
        if let Some(fd) = &self.fd {
            // SAFETY: wd belongs to this inotify instance. The kernel queues
            // IN_IGNORED; it is intentionally ignored by take_events because
            // the descriptor may be reused for a later registration.
            unsafe { libc::inotify_rm_watch(fd.as_raw_fd(), wd) };
        }
    }

    fn failed_registration(&mut self, errno: Option<i32>, missing_ok: bool) -> AddResult {
        if missing_ok && errno.is_some_and(|e| e == libc::ENOENT || e == libc::ENOTDIR) {
            return AddResult::Missing;
        }
        self.registration_failed = true;
        self.dirty = true;
        AddResult::Failed
    }

    /// Rebuild registrations after requested paths change or a stand-in
    /// directory changes. `tell` names paths to report on the next ask.
    fn rebuild(&mut self, tell: &HashSet<PathBuf>) {
        self.registration_failed = false;
        let mut existing = Vec::new();
        let mut absent = Vec::new();
        for p in &self.desired {
            if std::fs::metadata(p).is_ok() {
                existing.push(p.clone());
            } else {
                absent.push(p.clone());
            }
        }

        // Keep every still-requested exact registration alive. Re-registering
        // it would open a race in which an event can land between removing the
        // old watch and adding the new one.
        let stale_exact: Vec<(PathBuf, bool)> = self
            .nodes
            .iter()
            .filter_map(|(path, wd)| match self.by_fd.get(wd) {
                Some(Node::Exact(_)) if !self.desired.contains(path) => Some(path.clone()),
                Some(Node::Exact(_)) if !existing.iter().any(|p| p == path) => Some(path.clone()),
                _ => None,
            })
            .map(|path| {
                let still_desired = self.desired.contains(&path);
                (path, still_desired)
            })
            .collect();
        for (path, still_desired) in stale_exact {
            if still_desired {
                // The path disappeared before this rebuild. Report that
                // transition even when the caller re-applied the same set
                // before consuming the queued delete event.
                self.fresh.insert(path.clone());
            }
            self.remove_path(&path);
        }

        // A missing path may share its parent with an exact directory watch;
        // that exact watch also sees entry changes. A path that disappeared
        // between metadata(2) and inotify_add_watch(2) is treated as missing,
        // not as an unbounded wait on an unwatched path.
        self.missing = absent.into_iter().collect();
        for p in existing {
            match self.add_exact(&p) {
                AddResult::Added if tell.contains(&p) => {
                    self.fresh.insert(p);
                }
                AddResult::Missing => {
                    self.missing.insert(p);
                }
                _ => {}
            }
        }

        let needed_parents: HashSet<PathBuf> = self
            .missing
            .iter()
            .filter_map(|p| nearest_existing_parent(p))
            .collect();
        let stale_parents: Vec<PathBuf> = self
            .nodes
            .iter()
            .filter_map(|(path, wd)| match self.by_fd.get(wd) {
                Some(Node::Parent) if !needed_parents.contains(path) => Some(path.clone()),
                _ => None,
            })
            .collect();
        for path in stale_parents {
            self.remove_path(&path);
        }

        for parent in needed_parents {
            if !self.nodes.contains_key(&parent) {
                let _ = self.add_node(parent, Node::Parent, false);
            }
        }

        // A target can appear after the metadata pass but before its parent
        // stand-in is registered. Promote it now so that appearance does not
        // depend on a later directory event.
        let appeared: Vec<PathBuf> = self
            .missing
            .iter()
            .filter(|p| std::fs::metadata(p).is_ok())
            .cloned()
            .collect();
        for path in appeared {
            self.missing.remove(&path);
            match self.add_exact(&path) {
                AddResult::Added | AddResult::Already => {
                    self.fresh.insert(path);
                }
                AddResult::Missing => {
                    self.missing.insert(path);
                }
                AddResult::Failed => {}
            }
        }
    }

    fn add_exact(&mut self, path: &Path) -> AddResult {
        let path = path.to_path_buf();
        if let Some(&wd) = self.nodes.get(&path) {
            let was_exact = matches!(self.by_fd.get(&wd), Some(Node::Exact(_)));
            self.by_fd.insert(wd, Node::Exact(path));
            return if was_exact {
                AddResult::Already
            } else {
                AddResult::Added
            };
        }
        self.add_node(path.clone(), Node::Exact(path), true)
    }

    fn add_node(&mut self, path: PathBuf, node: Node, missing_ok: bool) -> AddResult {
        let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return self.failed_registration(None, false);
        };
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            return self.failed_registration(None, false);
        };
        #[cfg(test)]
        if let Some(errno) = self.add_watch_errno.take() {
            return self.failed_registration(Some(errno), missing_ok);
        }
        // SAFETY: c is NUL-terminated and fd is a live inotify descriptor.
        let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), MASK) };
        if wd < 0 {
            return self
                .failed_registration(std::io::Error::last_os_error().raw_os_error(), missing_ok);
        }
        if self.by_fd.contains_key(&wd) {
            // Linux can coalesce registrations that resolve to the same
            // inode (for example through aliases). Do not overwrite the
            // existing logical path: the second path is not independently
            // observable, so use the bounded dirty fallback instead.
            self.registration_failed = true;
            self.dirty = true;
            return AddResult::Failed;
        }
        self.nodes.insert(path, wd);
        self.by_fd.insert(wd, node);
        AddResult::Added
    }

    fn remove_fd(&mut self, wd: RawFd) {
        if let Some((path, _)) = self.nodes.iter().find(|(_, v)| **v == wd) {
            let path = path.clone();
            self.nodes.remove(&path);
        }
        self.by_fd.remove(&wd);
    }

    fn take_events(&mut self) {
        let Some(fd) = &self.fd else {
            return;
        };
        let fd = fd.as_raw_fd();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: buf is valid for writes and fd is nonblocking.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if e.raw_os_error() == Some(libc::EAGAIN)
                    || e.raw_os_error() == Some(libc::EWOULDBLOCK)
                {
                    break;
                }
                self.dirty = true;
                break;
            }
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            let end = n as usize;
            let header = std::mem::size_of::<libc::inotify_event>();
            while off + header <= end {
                // SAFETY: the kernel record is fully contained in buf. A
                // byte buffer has no alignment guarantee, so copy unaligned.
                let ev = unsafe {
                    std::ptr::read_unaligned(buf.as_ptr().add(off) as *const libc::inotify_event)
                };
                let len = ev.len as usize;
                if off + header + len > end {
                    self.dirty = true;
                    break;
                }
                let wd = ev.wd;
                let mask = ev.mask;
                if mask & libc::IN_Q_OVERFLOW != 0 {
                    self.dirty = true;
                } else if let Some(node) = self.by_fd.get(&wd).cloned() {
                    match node {
                        Node::Exact(path) => {
                            if mask & MASK != 0 {
                                self.fresh.insert(path.clone());
                            }
                            if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                                self.remove_fd(wd);
                                if self.desired.contains(&path) {
                                    self.missing.insert(path);
                                    self.resolve_missing();
                                }
                            }
                            // An exact directory can also be a stand-in for a
                            // deeper missing path.
                            if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                                self.resolve_missing();
                            }
                        }
                        Node::Parent => {
                            if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                                self.remove_fd(wd);
                            }
                            self.resolve_missing();
                        }
                    }
                }
                off += header + len;
            }
        }
    }

    fn resolve_missing(&mut self) {
        if self.missing.is_empty() {
            return;
        }
        let old = self.missing.clone();
        let appeared: HashSet<PathBuf> = old
            .iter()
            .filter(|p| std::fs::metadata(p).is_ok())
            .cloned()
            .collect();
        // Rebuild even when no target exists yet: a newly created directory
        // may move the stand-in one level deeper before its file arrives.
        // This keeps the wait entirely event-driven without a retry timer.
        self.rebuild(&appeared);
    }
}

fn inotify() -> Option<OwnedFd> {
    // SAFETY: no pointers are involved; flags request nonblocking and
    // close-on-exec behavior.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    (fd >= 0).then(|| {
        // SAFETY: fd is a descriptor returned by inotify_init1.
        unsafe { OwnedFd::from_raw_fd(fd) }
    })
}

fn wake_pipe() -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds points to two writable integers; pipe2 initializes both.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        return None;
    }
    // SAFETY: successful pipe2 returned two owned descriptors.
    Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn nearest_existing_parent(path: &Path) -> Option<PathBuf> {
    let mut p = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    loop {
        if std::fs::metadata(p).is_ok_and(|m| m.is_dir()) {
            return Some(p.to_path_buf());
        }
        p = p.parent().filter(|p| !p.as_os_str().is_empty())?;
    }
}

fn poll_timeout(timeout: Option<Duration>, until: Option<Instant>) -> i32 {
    let d = until
        .map(|u| u.saturating_duration_since(Instant::now()))
        .or(timeout)
        .unwrap_or(Duration::MAX);
    if d == Duration::MAX {
        -1
    } else {
        d.as_millis().min(i32::MAX as u128) as i32
    }
}

/// A failed registration cannot be served by inotify. Keep the fallback
/// bounded so callers periodically re-check their paths, while avoiding a
/// tight stat loop. A Stop still cancels it immediately.
const REGISTRATION_FALLBACK: Duration = Duration::from_secs(2);

/// Blocks until one of files differs in size or identity, or stop closes.
pub fn grown(stop: &Stop, files: &[File]) -> bool {
    if changed(files) {
        return true;
    }
    let watcher = Watcher::new();
    #[cfg(test)]
    watched::before_watch(files);
    watcher.watch(&files.iter().map(|f| f.path.clone()).collect::<Vec<_>>());
    // A write may land after the first check but before inotify_add_watch(2).
    // This second check closes that registration race; subsequent writes are
    // queued by the watch itself.
    if changed(files) {
        return true;
    }
    loop {
        if !watcher.wait(Some(stop), None) {
            return false;
        }
        if changed(files) || (!watcher.registration_failed() && watcher.changed()) {
            return true;
        }
    }
}

/// Notices writes to files and folders using one inotify descriptor.
pub struct Watcher {
    inner: Mutex<Inner>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Watcher {
    pub fn new() -> Watcher {
        Watcher {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// inotify already multiplexes all paths through one descriptor.
    pub fn many() -> Watcher {
        Self::new()
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn watch<P: AsRef<Path>>(&self, paths: &[P]) {
        let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if w.closed {
            return;
        }
        if w.fd.is_none() {
            w.desired = paths.iter().map(|p| p.as_ref().to_path_buf()).collect();
            w.registration_failed = true;
            w.dirty = true;
            return;
        }
        let old_desired = std::mem::take(&mut w.desired);
        let old_watched: HashSet<PathBuf> = w
            .by_fd
            .values()
            .filter_map(|node| match node {
                Node::Exact(path) => Some(path.clone()),
                Node::Parent => None,
            })
            .collect();
        w.desired = paths.iter().map(|p| p.as_ref().to_path_buf()).collect();
        let tell: HashSet<PathBuf> = w
            .desired
            .iter()
            .filter(|p| !old_desired.contains(*p) || !old_watched.contains(*p))
            .cloned()
            .collect();
        w.rebuild(&tell);
    }

    pub fn watching(&self, path: impl AsRef<Path>) -> bool {
        let w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        matches!(
            w.nodes.get(path.as_ref()).and_then(|wd| w.by_fd.get(wd)),
            Some(Node::Exact(p)) if p == path.as_ref()
        )
    }

    pub fn changed(&self) -> bool {
        let (paths, all) = self.changes();
        all || !paths.is_empty()
    }

    fn registration_failed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .registration_failed
    }

    pub fn changes(&self) -> (HashSet<PathBuf>, bool) {
        let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if w.fd.is_none() {
            return (HashSet::new(), true);
        }
        let all = std::mem::replace(&mut w.dirty, false);
        w.take_events();
        let all = all || std::mem::replace(&mut w.dirty, false);
        (std::mem::take(&mut w.fresh), all)
    }

    fn registration_fallback(&self, stop: Option<&Stop>, timeout: Option<Duration>) -> bool {
        let d = timeout
            .map(|d| d.min(REGISTRATION_FALLBACK))
            .unwrap_or(REGISTRATION_FALLBACK);
        let stopped = match stop {
            Some(stop) => stop.wait(d),
            None => {
                std::thread::sleep(d);
                false
            }
        };
        if !stopped {
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !w.closed {
                w.dirty = true;
            }
        }
        !stopped
    }

    /// Blocks in poll(2) on inotify and Stop's cancellation pipe. Unrelated
    /// stand-in events are drained and the wait continues.
    pub fn wait(&self, stop: Option<&Stop>, timeout: Option<Duration>) -> bool {
        let (fd, wake, until, closed, registration_failed) = {
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            w.dirty = false;
            w.fresh.clear();
            (
                w.fd.as_ref().and_then(|fd| fd.try_clone().ok()),
                w.wake_r.as_ref().and_then(|fd| fd.try_clone().ok()),
                timeout.map(|d| Instant::now() + d),
                w.closed,
                w.registration_failed,
            )
        };
        if closed {
            return true;
        }
        if registration_failed {
            return self.registration_fallback(stop, timeout);
        }
        let Some(fd) = fd else {
            return self.registration_fallback(stop, timeout);
        };
        if stop.is_some_and(Stop::is_closed) {
            return false;
        }
        loop {
            let mut fds = vec![libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let wake_index = wake.as_ref().map(|wake| {
                fds.push(libc::pollfd {
                    fd: wake.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                fds.len() - 1
            });
            if let Some(stop) = stop {
                fds.push(libc::pollfd {
                    fd: stop.r.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            let ms = poll_timeout(timeout, until);
            // SAFETY: all fds are live and poll writes only revents.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, ms) };
            if n < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return false;
            }
            if stop.is_some_and(Stop::is_closed) {
                return false;
            }
            if n == 0 {
                return true;
            }
            if wake_index.is_some_and(|i| fds[i].revents != 0) {
                let mut buf = [0u8; 64];
                if let Some(wake) = wake.as_ref() {
                    // SAFETY: buf is valid and wake is a nonblocking pipe.
                    unsafe { libc::read(wake.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                }
                // close() writes this wake byte before removing inotify, so
                // return and let the caller observe the closed state.
                if self.inner.lock().unwrap_or_else(|e| e.into_inner()).closed {
                    return true;
                }
            }
            if fds[0].revents != 0 {
                let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                w.take_events();
                if w.dirty || !w.fresh.is_empty() {
                    return true;
                }
            }
            if until.is_some_and(|u| u <= Instant::now()) {
                return true;
            }
        }
    }

    pub fn close(&self) {
        let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if w.closed {
            return;
        }
        w.closed = true;
        if let Some(wake) = &w.wake_w {
            let byte = [1u8];
            // SAFETY: byte is valid and wake is a nonblocking pipe writer.
            unsafe { libc::write(wake.as_raw_fd(), byte.as_ptr().cast(), 1) };
        }
        w.remove_nodes();
        w.fd.take();
        w.desired.clear();
        w.missing.clear();
        w.fresh.clear();
        w.dirty = true;
    }
}

#[cfg(test)]
pub(crate) mod watched {
    use super::File;
    use std::path::{Path, PathBuf};
    use std::sync::{Condvar, Mutex};

    static W: (Mutex<Vec<PathBuf>>, Condvar) = (Mutex::new(Vec::new()), Condvar::new());

    /// Signals after grown's initial stat and immediately before registration.
    pub(crate) fn before_watch(files: &[File]) {
        W.0.lock()
            .unwrap()
            .extend(files.iter().map(|f| f.path.clone()));
        W.1.notify_all();
    }

    /// Blocks until grown reaches its registration boundary for p.
    pub(crate) fn wait_before_watch(path: &Path) {
        let g = W.0.lock().unwrap();
        let _g =
            W.1.wait_while(g, |paths| !paths.iter().any(|p| p == path))
                .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::mpsc;

    #[test]
    fn inotify_reports_append_missing_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        let w = Arc::new(Watcher::new());
        w.watch(&[&path]);
        assert!(w.changed());
        assert!(!w.changed());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"b\n").unwrap();
        drop(f);
        assert!(w.wait(None, Some(Duration::from_secs(2))));
        assert!(w.changes().0.contains(&path));

        let missing = dir.path().join("jobs").join("state.json");
        let missing_w = Arc::new(Watcher::new());
        missing_w.watch(&[&missing]);
        std::fs::create_dir(dir.path().join("jobs")).unwrap();
        std::fs::write(&missing, "{}").unwrap();
        assert!(missing_w.wait(None, Some(Duration::from_secs(2))));
        assert!(missing_w.changes().0.contains(&missing));

        let stop = Arc::new(Stop::new().unwrap());
        let (tx, rx) = mpsc::channel();
        let wait_w = w.clone();
        let wait_stop = stop.clone();
        std::thread::spawn(move || tx.send(wait_w.wait(Some(&wait_stop), None)).unwrap());
        stop.close();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)), Ok(false));

        let close_w = Arc::new(Watcher::new());
        close_w.watch(&[&path]);
        let (tx, rx) = mpsc::channel();
        let waiter = close_w.clone();
        std::thread::spawn(move || tx.send(waiter.wait(None, None)).unwrap());
        close_w.close();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)), Ok(true));
    }

    #[test]
    fn grown_catches_write_between_stat_and_registration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        let stop = Arc::new(Stop::new().unwrap());
        let (tx, rx) = mpsc::channel();
        let grown_stop = stop.clone();
        let grown_path = path.clone();
        std::thread::spawn(move || {
            tx.send(grown(
                &grown_stop,
                &[File {
                    path: grown_path,
                    size: 2,
                }],
            ))
            .unwrap();
        });
        watched::wait_before_watch(&path);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"b\n").unwrap();
        drop(f);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)), Ok(true));
        stop.close();
    }

    #[test]
    fn watch_preserves_queued_exact_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queued.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        let w = Watcher::new();
        w.watch(&[&path]);
        w.changes();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"b\n").unwrap();
        drop(f);
        // Reapplying the same path set must not tear down the registration or
        // lose the event already queued for it.
        w.watch(&[&path]);
        assert!(w.changes().0.contains(&path));
    }

    #[test]
    fn close_before_wait_returns_without_sleeping() {
        let w = Watcher::new();
        w.close();
        let started = std::time::Instant::now();
        assert!(w.wait(None, None));
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn failed_registration_is_bounded_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enospc.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        let w = Arc::new(Watcher::new());
        {
            let mut inner = w.inner();
            inner.add_watch_errno = Some(libc::ENOSPC);
        }
        w.watch(&[&path]);
        assert!(w.changed());
        let started = std::time::Instant::now();
        assert!(w.wait(None, Some(Duration::from_millis(20))));
        assert!(started.elapsed() < Duration::from_millis(500));

        // A stand-in registration can fail too (for example when the inotify
        // watch limit is exhausted); it must take the same bounded path.
        let missing = dir.path().join("missing").join("state.json");
        let standin = Watcher::new();
        {
            let mut inner = standin.inner();
            inner.add_watch_errno = Some(libc::ENOSPC);
        }
        standin.watch(&[&missing]);
        assert!(standin.changed());
        let started = std::time::Instant::now();
        assert!(standin.wait(None, Some(Duration::from_millis(20))));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn disappearing_registration_becomes_a_standin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanishes.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        let w = Watcher::new();
        {
            let mut inner = w.inner();
            inner.add_watch_errno = Some(libc::ENOENT);
        }
        w.watch(&[&path]);
        assert!(!w.watching(&path));
        assert!(w.inner().missing.contains(&path));
    }
}
