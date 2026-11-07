//! Waiting for a process that isn't ours to go: the node process a gate
//! holder holds a run for. Go looks every 250ms (cmd/rush/gate.go:416);
//! here kqueue/pidfd says the moment it exits, and elsewhere it's still a
//! look every 250ms.

use rush_sys::proc::{self, Pid};

/// Whether pid runs: it answers kill and isn't a zombie.
fn runs(pid: Pid) -> bool {
    proc::kill(pid, 0).is_ok() && !proc::zombie(pid)
}

/// Returns once pid has gone.
pub fn wait_gone(pid: Pid) {
    if wait_kernel(pid) {
        return;
    }
    let c = crate::gate::Cancel::new();
    while runs(pid) {
        c.wait(std::time::Duration::from_millis(250));
    }
}

/// Waits on macOS's process filter for pid's exit; false when it can't, to
/// look instead.
#[cfg(target_os = "macos")]
fn wait_kernel(pid: Pid) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: kqueue takes nothing; a non-negative result is ours.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return false;
    }
    // SAFETY: kq is a descriptor we just made.
    let kq = unsafe { OwnedFd::from_raw_fd(kq) };
    // SAFETY: kevent is plain data.
    let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
    ev.ident = pid as usize;
    ev.filter = libc::EVFILT_PROC;
    ev.flags = libc::EV_ADD | libc::EV_ONESHOT;
    ev.fflags = libc::NOTE_EXIT;
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
        return !runs(pid); // gone already, or not ours to watch
    }
    // Watched now, so it can't exit unseen; it may have before.
    if !runs(pid) {
        return true;
    }
    loop {
        // SAFETY: kevent is plain data.
        let mut out: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: room for one event; no timeout, so it blocks.
        let n = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                std::ptr::null(),
                0,
                &mut out,
                1,
                std::ptr::null(),
            )
        };
        if n > 0 {
            return true;
        }
        if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}

/// Linux's pidfd gives a race-free death notification for a non-child.  It is
/// pollable and remains tied to this process instance even if the numeric PID
/// is reused after exit.
#[cfg(target_os = "linux")]
fn wait_kernel(pid: Pid) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: pidfd_open takes plain integers and returns a new descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    if fd < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) || !runs(pid);
    }
    // SAFETY: the non-negative descriptor is newly owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        // SAFETY: pfd points to one initialized pollfd on this stack.
        let n = unsafe { libc::poll(&mut pfd, 1, -1) };
        if n > 0 {
            return true;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return !runs(pid);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn wait_kernel(_pid: Pid) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_when_it_goes() {
        let mut c = std::process::Command::new("sh")
            .args(["-c", "read _"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = c.id() as Pid;
        let h = std::thread::spawn(move || wait_gone(pid));
        drop(c.stdin.take()); // it reads the end, and exits
        let _ = c.wait();
        h.join().unwrap();
        wait_gone(pid); // gone already
    }
}
