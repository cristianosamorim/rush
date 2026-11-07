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

pub(crate) struct Inner {
    fd: Option<OwnedFd>,
    wake_r: Option<OwnedFd>,
    wake_w: Option<OwnedFd>,
    desired: HashSet<PathBuf>,
    missing: HashSet<PathBuf>,
    nodes: HashMap<PathBuf, RawFd>,
    by_fd: HashMap<RawFd, Node>,
    fresh: HashSet<PathBuf>,
    dirty: bool,
}

impl Inner {
    fn new() -> Inner {
        let (wake_r, wake_w) = match wake_pipe() {
            Some((r, w)) => (Some(r), Some(w)),
            None => (None, None),
        };
        Inner {
            fd: inotify(),
            wake_r,
            wake_w,
            desired: HashSet::new(),
            missing: HashSet::new(),
            nodes: HashMap::new(),
            by_fd: HashMap::new(),
            fresh: HashSet::new(),
            dirty: true,
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

    /// Rebuild registrations after requested paths change or a stand-in
    /// directory changes. `tell` names paths to report on the next ask.
    fn rebuild(&mut self, tell: &HashSet<PathBuf>) {
        self.remove_nodes();
        self.missing.clear();
        let mut existing = Vec::new();
        let mut absent = Vec::new();
        for p in &self.desired {
            if std::fs::metadata(p).is_ok() {
                existing.push(p.clone());
            } else {
                absent.push(p.clone());
            }
        }
        // Register real paths first. A missing path may share its parent with
        // an exact directory watch; that exact watch also sees entry changes.
        for p in existing {
            if self.add_exact(&p) && tell.contains(&p) {
                self.fresh.insert(p);
            }
        }
        for p in absent {
            self.missing.insert(p);
        }
        let missing = self.missing.clone();
        for p in missing {
            let Some(parent) = nearest_existing_parent(&p) else {
                continue;
            };
            if !self.nodes.contains_key(&parent) {
                let _ = self.add_node(parent, Node::Parent);
            }
        }
    }

    fn add_exact(&mut self, path: &Path) -> bool {
        let path = path.to_path_buf();
        if self.nodes.contains_key(&path) {
            if let Some(&wd) = self.nodes.get(&path) {
                self.by_fd.insert(wd, Node::Exact(path));
            }
            return true;
        }
        self.add_node(path.clone(), Node::Exact(path))
    }

    fn add_node(&mut self, path: PathBuf, node: Node) -> bool {
        let Some(fd) = &self.fd else {
            return false;
        };
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: c is NUL-terminated and fd is a live inotify descriptor.
        let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), MASK) };
        if wd < 0 {
            return false;
        }
        self.nodes.insert(path, wd);
        self.by_fd.insert(wd, node);
        true
    }

    fn remove_fd(&mut self, wd: RawFd) {
        if let Some((path, _)) = self.nodes.iter().find(|(_, &v)| v == wd) {
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

/// Blocks until one of files differs in size or identity, or stop closes.
pub fn grown(stop: &Stop, files: &[File]) -> bool {
    if changed(files) {
        return true;
    }
    let watcher = Watcher::new();
    watcher.watch(&files.iter().map(|f| f.path.clone()).collect::<Vec<_>>());
    loop {
        if !watcher.wait(Some(stop), None) {
            return false;
        }
        if watcher.changed() || changed(files) {
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
        if w.fd.is_none() {
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

    /// Blocks in poll(2) on inotify and Stop's cancellation pipe. Unrelated
    /// stand-in events are drained and the wait continues.
    pub fn wait(&self, stop: Option<&Stop>, timeout: Option<Duration>) -> bool {
        let (fd, wake, until) = {
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            w.dirty = false;
            w.fresh.clear();
            (
                w.fd.as_ref().and_then(|fd| fd.try_clone().ok()),
                w.wake_r.as_ref().and_then(|fd| fd.try_clone().ok()),
                timeout.map(|d| Instant::now() + d),
            )
        };
        let Some(fd) = fd else {
            return match stop {
                Some(stop) => !stop.wait(timeout.unwrap_or(Duration::from_secs(2))),
                None => {
                    std::thread::sleep(timeout.unwrap_or(Duration::from_secs(2)));
                    true
                }
            };
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
                if self
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .fd
                    .is_none()
                {
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
}
