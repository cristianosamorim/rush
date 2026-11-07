//! The host's own wait (Rust-only): one kqueue, on the thread that serves
//! the host, holds what Go gives a goroutine each (host.go:698 accept,
//! :661 watchSock, :681 watchOwner): its socket's listener, its folder (it
//! stops once its socket is gone), the process that started it (it stops
//! once that's gone) and its quitting. Nothing in it is a timer: between
//! turns it wakes for nothing, where Go looks every 30 s and every second.
//! The look at its tmp (trim.go) is a job on the host's timers rather than
//! a thread of its own.
//!
//! Where the kqueue can't be made, a thread waits on each as before
//! (serve_on).

use std::os::fd::{AsRawFd, OwnedFd};

use super::*;

/// A pipe the host's wait reads: written as the host quits.
pub(super) struct Wake {
    r: OwnedFd,
    w: OwnedFd,
}

impl Wake {
    pub(super) fn new() -> Option<Wake> {
        let (r, w) = std::io::pipe().ok()?;
        let (r, w) = (OwnedFd::from(r), OwnedFd::from(w));
        for fd in [r.as_raw_fd(), w.as_raw_fd()] {
            // SAFETY: O_NONBLOCK on our own pipe: a read drains it, a write
            // never waits.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        Some(Wake { r, w })
    }

    /// Wakes the wait.
    pub(super) fn ring(&self) {
        // SAFETY: one byte into our own pipe; a full pipe wakes it already.
        unsafe { libc::write(self.w.as_raw_fd(), b"x".as_ptr().cast(), 1) };
    }

    fn drain(&self) {
        let mut b = [0u8; 64];
        // SAFETY: reads into our buffer from our non-blocking pipe.
        while unsafe { libc::read(self.r.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) } > 0 {}
    }
}

#[cfg(target_os = "macos")]
fn kevent_of(ident: usize, filter: i16, flags: u16, fflags: u32) -> libc::kevent {
    // SAFETY: kevent is plain data.
    let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
    ev.ident = ident;
    ev.filter = filter;
    ev.flags = flags;
    ev.fflags = fflags;
    ev
}

/// Registers one change on kq: whether it took, and the error when not.
#[cfg(target_os = "macos")]
fn change(kq: &OwnedFd, ev: libc::kevent) -> std::io::Result<()> {
    // SAFETY: one valid change, no events read.
    let r = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            &ev,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// What a change to the folder itself (not an entry in it) says: it's
/// gone or moved, so it's watched again by its path.
#[cfg(target_os = "macos")]
const FOLDER_GONE: u32 = libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE;

/// Watches dir's entries on kq: its descriptor, which stops the watch as
/// it closes; None when it can't be opened.
#[cfg(target_os = "macos")]
fn watch_folder(kq: &OwnedFd, dir: &Path) -> Option<OwnedFd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: c is a NUL-terminated path.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_EVTONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: a descriptor we just opened.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let ev = kevent_of(
        fd.as_raw_fd() as usize,
        libc::EVFILT_VNODE,
        libc::EV_ADD | libc::EV_CLEAR,
        libc::NOTE_WRITE | FOLDER_GONE,
    );
    change(kq, ev).ok()?;
    Some(fd)
}

/// Takes the client ln has waiting without waiting for one: a client that
/// dialled and went before it was taken leaves none, and a wait here
/// would wait past the host's quitting. Non-blocking only for the call,
/// as the listener is handed on across an upgrade's exec as it was.
fn accept_now(ln: &UnixListener) -> std::io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
    ln.set_nonblocking(true)?;
    let c = ln.accept();
    let _ = ln.set_nonblocking(false);
    let (c, a) = c?;
    // What it takes is as accept's always is: blocking.
    c.set_nonblocking(false)?;
    Ok((c, a))
}

impl Host {
    /// Looks every TRIM_EVERY whether to trim the session's tmp, as long
    /// as the host runs.
    pub(super) fn arm_trim(&self) {
        let h = self.clone();
        self.timers
            .after(crate::trim::TRIM_EVERY, move || h.trim_due());
    }

    /// The look: its cheap part on the timers' thread, what's open under
    /// the tmp (which takes a while to tell) and the trim on one of its
    /// own, only when the disk is low.
    fn trim_due(&self) {
        if self.lock().quit {
            return;
        }
        self.arm_trim();
        if !rush_state::Store::load().config.trim_running_tmp {
            return;
        }
        let id = self.lock().cfg.id.clone();
        let tmp = crate::tmp::temp_dir(&id);
        if !crate::trim::disk_low(&tmp) {
            return;
        }
        self.go("trim", move |_| {
            let Some(held) = crate::trim::held_under(&tmp) else {
                return; // without knowing what's open, nothing is safe to remove
            };
            let n = crate::trim::trim_tmp(&tmp, SystemTime::now(), &held);
            if n > 0 {
                log_event(&id, "tmp-trimmed", json!({"removed": n}));
            }
        });
    }

    /// Stops the host for why, on a thread of its own, as a watcher of
    /// Go's does: the wait goes on serving clients meanwhile.
    fn stop_for(&self, why: Value) {
        let st = self.lock();
        if st.quit {
            return;
        }
        self.event(&st, "stopping", why);
        drop(st);
        let h = self.clone();
        self.go("stop", move |_| {
            let _ = h.do_op(Op::named("stop"));
        });
    }

    /// Serves ln's clients and watches sock and owner (when it's given)
    /// in one kqueue on this thread, until the host quits: true then.
    /// False at once when the wait can't be made: the caller's threads
    /// do it. What can't be watched so is watched by a thread as before.
    #[cfg(target_os = "macos")]
    pub(super) fn serve_kq(&self, ln: &UnixListener, sock: &Path, owner: Option<i64>) -> bool {
        use std::os::fd::{FromRawFd, RawFd};
        let Some(wake) = &self.wake else {
            return false;
        };
        // SAFETY: kqueue takes nothing; a non-negative result is ours.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return false;
        }
        // SAFETY: as above.
        let kq = unsafe { OwnedFd::from_raw_fd(kq) };
        // SAFETY: kq is ours.
        unsafe { libc::fcntl(kq.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        let listen: RawFd = ln.as_raw_fd();
        let woken: RawFd = wake.r.as_raw_fd();
        for fd in [listen, woken] {
            let ev = kevent_of(fd as usize, libc::EVFILT_READ, libc::EV_ADD, 0);
            if change(&kq, ev).is_err() {
                return false;
            }
        }
        let dir = sock.parent().map(Path::to_path_buf).unwrap_or_default();
        let mut folder = watch_folder(&kq, &dir);
        let mut sock_watched = true;
        if folder.is_none() {
            // Not watched here: by a thread, as before.
            sock_watched = false;
            let h = self.clone();
            let s = sock.to_path_buf();
            self.go("sock", move |_| h.watch_sock(&s));
        }
        let mut owner_gone = false;
        if let Some(pid) = owner {
            let ev = kevent_of(
                pid as usize,
                libc::EVFILT_PROC,
                libc::EV_ADD | libc::EV_ONESHOT,
                libc::NOTE_EXIT,
            );
            match change(&kq, ev) {
                // Watched now, so it can't exit unseen; but it may already
                // be a zombie.
                Ok(()) => owner_gone = !crate::alive(pid),
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => owner_gone = true,
                Err(_) => {
                    let h = self.clone();
                    self.go("owner", move |_| h.watch_owner(pid));
                }
            }
        }
        let mut accepting = true;
        // SAFETY: kevent is plain data.
        let mut evs: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
        loop {
            if self.lock().quit {
                return true;
            }
            if sock_watched && std::fs::symlink_metadata(sock).is_err() {
                // No client can reach it again, so it would only linger.
                sock_watched = false;
                drop(folder.take());
                self.stop_for(json!({"why": "its socket is gone"}));
            }
            if owner_gone {
                owner_gone = false;
                let owner = owner.unwrap_or_default();
                self.stop_for(
                    json!({"why": "the process that started it is gone", "owner": owner}),
                );
            }
            // SAFETY: room for evs.len() events; no timeout: it waits for
            // one of them.
            let n = unsafe {
                libc::kevent(
                    kq.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    evs.as_mut_ptr(),
                    evs.len() as libc::c_int,
                    std::ptr::null(),
                )
            };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            for ev in &evs[..n as usize] {
                match ev.filter {
                    libc::EVFILT_READ if ev.ident == listen as usize => {
                        if !accepting {
                            continue;
                        }
                        let c = accept_now(ln);
                        if self.lock().quit {
                            return true;
                        }
                        match c {
                            Ok((c, _)) => {
                                let h = self.clone();
                                self.go("client", move |_| h.serve(c));
                            }
                            // Dialled and gone before it was taken.
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::ConnectionAborted
                                ) => {}
                            Err(_) => {
                                // As Go's accept loop, it ends on an error.
                                accepting = false;
                                let ev = kevent_of(
                                    listen as usize,
                                    libc::EVFILT_READ,
                                    libc::EV_DELETE,
                                    0,
                                );
                                let _ = change(&kq, ev);
                            }
                        }
                    }
                    libc::EVFILT_READ => wake.drain(),
                    libc::EVFILT_VNODE => {
                        if ev.fflags & FOLDER_GONE != 0 && sock_watched {
                            // The old descriptor's watch ends as it closes.
                            drop(folder.take());
                            folder = watch_folder(&kq, &dir);
                        }
                    }
                    libc::EVFILT_PROC => owner_gone = true,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn epoll_add(epoll: std::os::fd::RawFd, fd: std::os::fd::RawFd, tag: u64) -> std::io::Result<()> {
    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLERR | libc::EPOLLHUP) as u32,
        u64: tag,
    };
    // SAFETY: epoll and fd are descriptors owned by the caller, and event is
    // a valid epoll_event for the duration of the call.
    let r = unsafe { libc::epoll_ctl(epoll, libc::EPOLL_CTL_ADD, fd, &mut event) };
    (r == 0)
        .then_some(())
        .ok_or_else(std::io::Error::last_os_error)
}

#[cfg(target_os = "linux")]
fn watch_folder_linux(dir: &Path) -> Option<OwnedFd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: path is NUL-terminated and flags are the inotify_init1 flags.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let flags = libc::IN_ATTRIB
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MODIFY
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_MOVE_SELF
        | libc::IN_CLOSE_WRITE;
    // SAFETY: fd is a valid inotify descriptor and path is NUL-terminated.
    if unsafe { libc::inotify_add_watch(fd, path.as_ptr(), flags) } < 0 {
        // SAFETY: fd was created above and has not been wrapped yet.
        unsafe { libc::close(fd) };
        return None;
    }
    // SAFETY: a non-negative descriptor created by inotify_init1 is ours.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn drain_inotify(fd: std::os::fd::RawFd) -> bool {
    let mut changed = false;
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: buf is writable for its complete length and fd is a
        // non-blocking inotify descriptor owned by the caller.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            changed = true;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    changed
}

impl Host {
    /// Linux equivalent of the macOS kqueue wait: epoll serves clients and
    /// the quit pipe, inotify wakes when the socket's folder changes, and a
    /// pidfd reports the owner's death without a polling loop.
    #[cfg(target_os = "linux")]
    pub(super) fn serve_kq(&self, ln: &UnixListener, sock: &Path, owner: Option<i64>) -> bool {
        use std::os::fd::{FromRawFd, RawFd};

        let Some(wake) = &self.wake else {
            return false;
        };
        // SAFETY: epoll_create1 takes flags and returns a new descriptor.
        let epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll < 0 {
            return false;
        }
        // SAFETY: epoll_create1 returned a descriptor owned by this method.
        let epoll = unsafe { OwnedFd::from_raw_fd(epoll) };
        const LISTEN: u64 = 1;
        const WAKE: u64 = 2;
        const FOLDER: u64 = 3;
        const OWNER: u64 = 4;
        let listen = ln.as_raw_fd();
        if epoll_add(epoll.as_raw_fd(), listen, LISTEN).is_err()
            || epoll_add(epoll.as_raw_fd(), wake.r.as_raw_fd(), WAKE).is_err()
        {
            return false;
        }

        let dir = sock.parent().map(Path::to_path_buf).unwrap_or_default();
        let folder = watch_folder_linux(&dir);
        if let Some(folder) = &folder {
            if epoll_add(epoll.as_raw_fd(), folder.as_raw_fd(), FOLDER).is_err() {
                return false;
            }
        } else {
            // inotify is unavailable on an unusual proc/container setup;
            // keep the socket semantics by using the existing watcher.
            let h = self.clone();
            let s = sock.to_path_buf();
            self.go("sock", move |_| h.watch_sock(&s));
        }

        let mut _owner_fd = None;
        let mut owner_gone = false;
        if let Some(pid) = owner {
            // SAFETY: pidfd_open takes a pid and flags, both plain integers.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
            if fd >= 0 {
                // SAFETY: this descriptor was returned by pidfd_open above.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                if epoll_add(epoll.as_raw_fd(), fd.as_raw_fd(), OWNER).is_err() {
                    return false;
                }
                _owner_fd = Some(fd);
            } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                owner_gone = true;
            } else {
                let h = self.clone();
                self.go("owner", move |_| h.watch_owner(pid));
            }
        }

        let mut accepting = true;
        let mut sock_watched = true;
        // SAFETY: epoll_event is plain data.
        let mut events: [libc::epoll_event; 8] = unsafe { std::mem::zeroed() };
        loop {
            if self.lock().quit {
                return true;
            }
            if sock_watched && std::fs::symlink_metadata(sock).is_err() {
                sock_watched = false;
                self.stop_for(serde_json::json!({"why": "its socket is gone"}));
            }
            if owner_gone {
                owner_gone = false;
                let owner = owner.unwrap_or_default();
                self.stop_for(serde_json::json!({
                    "why": "the process that started it is gone",
                    "owner": owner
                }));
            }
            // SAFETY: events has room for eight events and epoll is owned by
            // this method.  A negative result is handled below.
            let n = unsafe {
                libc::epoll_wait(
                    epoll.as_raw_fd(),
                    events.as_mut_ptr(),
                    events.len() as libc::c_int,
                    -1,
                )
            };
            if n < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return false;
            }
            for event in &events[..n as usize] {
                match event.u64 {
                    LISTEN if accepting => match accept_now(ln) {
                        Ok((c, _)) => {
                            if self.lock().quit {
                                return true;
                            }
                            let h = self.clone();
                            self.go("client", move |_| h.serve(c));
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::ConnectionAborted
                            ) => {}
                        Err(_) => {
                            accepting = false;
                            // SAFETY: epoll and listen are valid descriptors;
                            // deleting a missing registration is harmless.
                            unsafe {
                                libc::epoll_ctl(
                                    epoll.as_raw_fd(),
                                    libc::EPOLL_CTL_DEL,
                                    listen,
                                    std::ptr::null_mut(),
                                );
                            }
                        }
                    },
                    WAKE => wake.drain(),
                    FOLDER => {
                        if let Some(folder) = &folder
                            && drain_inotify(folder.as_raw_fd())
                            && sock_watched
                            && std::fs::symlink_metadata(sock).is_err()
                        {
                            sock_watched = false;
                            self.stop_for(serde_json::json!({"why": "its socket is gone"}));
                        }
                    }
                    OWNER => {
                        owner_gone = true;
                        // A dead pidfd stays readable. Close it after
                        // the first notification, as EV_ONESHOT does on
                        // macOS, so draining a session cannot spin.
                        drop(_owner_fd.take());
                    }
                    _ => {}
                }
            }
        }
    }
}
