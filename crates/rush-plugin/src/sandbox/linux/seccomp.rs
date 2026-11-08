//! Linux counterpart of internal/plugin/sandbox_darwin.go:28: processes and
//! sockets stay inside the approved plugin boundary. Linux's first exec
//! is authorized once by the trusted parent; later execs have no listener.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const USER_NOTIF: u32 = 0x7fc0_0000;
const ALLOW: u32 = 0x7fff_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
const ERRNO: u32 = 0x0005_0000;
const NEW_LISTENER: libc::c_ulong = 8;
const CONTINUE: u32 = 1;

#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xc000_00b7;

// linux/seccomp.h and asm-generic/ioctl.h. These layouts are identical on
// the two native 64-bit ABIs supported by this backend.
#[repr(C)]
#[derive(Default)]
struct Data {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    data: Data,
}

#[repr(C)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}

const RECV: libc::c_ulong = 0xc050_2100;
const SEND: libc::c_ulong = 0xc018_2101;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

const LOAD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const EQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const GT: u16 = 0x25; // BPF_JMP | BPF_JGT | BPF_K
#[cfg(target_arch = "x86_64")]
const GE: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const SET: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const AND: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
const RET: u16 = 0x06;

/// A small forward-only cBPF builder. A syscall clause either returns a
/// verdict or skips its entire body to the next clause.
struct Filter(Vec<libc::sock_filter>);

impl Filter {
    fn syscall(&mut self, nr: libc::c_long, body: &[libc::sock_filter]) {
        self.0.push(stmt(LOAD, 0));
        self.0
            .push(jump(EQ, nr as u32, 0, body.len().try_into().unwrap()));
        self.0.extend_from_slice(body);
    }

    fn verdict(&mut self, nr: libc::c_long, verdict: u32) {
        self.syscall(nr, &[stmt(RET, verdict)]);
    }
}

fn arg(n: u32) -> libc::sock_filter {
    stmt(LOAD, 16 + n * 8)
}

/// Install in a single-threaded trusted bootstrap. Its network helper
/// must already have forked, and must not inherit this listener. The
/// caller sends the listener to the parent, CLOSES its own copy, then
/// immediately execs the approved command. No plugin code runs before it.
pub(super) fn install(network: bool) -> io::Result<OwnedFd> {
    let denied = ERRNO | libc::EPERM as u32;
    let mut f = Filter(vec![
        stmt(LOAD, 4),
        jump(EQ, ARCH, 1, 0),
        stmt(RET, KILL_PROCESS),
    ]);
    #[cfg(target_arch = "x86_64")]
    f.0.extend([
        stmt(LOAD, 0),
        jump(SET, 0x4000_0000, 0, 1), // no x32 syscall ABI
        stmt(RET, KILL_PROCESS),
    ]);
    // Pin the accepted syscall ABI to Linux 6.8. New host kernels must
    // not silently introduce an unchecked process/socket API. ENOSYS
    // lets runtimes use their fallback for genuinely optional new calls.
    f.0.extend([
        stmt(LOAD, 0),
        jump(GT, 461, 0, 1),
        stmt(RET, ERRNO | libc::ENOSYS as u32),
    ]);
    #[cfg(target_arch = "x86_64")]
    f.0.extend([
        stmt(LOAD, 0),
        jump(GE, 335, 0, 2),
        jump(GT, 423, 1, 0),
        stmt(RET, ERRNO | libc::ENOSYS as u32),
    ]);
    for nr in [libc::SYS_execve, libc::SYS_execveat] {
        f.verdict(nr, USER_NOTIF);
    }
    // A new USER_NOTIF filter could otherwise replace the closed listener
    // at equal precedence and let two malicious threads approve an exec.
    f.verdict(libc::SYS_seccomp, denied);
    f.syscall(
        libc::SYS_prctl,
        &[
            arg(0),
            jump(EQ, libc::PR_SET_SECCOMP as u32, 0, 1),
            stmt(RET, denied),
            stmt(RET, ALLOW),
        ],
    );
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_fork, libc::SYS_vfork] {
        f.verdict(nr, denied);
    }
    // clone3's pointed-to arguments cannot be checked by cBPF. ENOSYS
    // requests libc's ordinary clone fallback for pthread_create.
    f.verdict(libc::SYS_clone3, ERRNO | libc::ENOSYS as u32);
    let required = libc::CLONE_THREAD | libc::CLONE_VM | libc::CLONE_SIGHAND;
    let thread_flags = required
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_SETTID
        | libc::CLONE_CHILD_CLEARTID;
    f.syscall(
        libc::SYS_clone,
        &[
            stmt(LOAD, 20), // high half of the native clone flags
            jump(EQ, 0, 1, 0),
            stmt(RET, denied),
            arg(0),
            stmt(AND, !thread_flags as u32),
            jump(EQ, 0, 1, 0),
            stmt(RET, denied),
            arg(0),
            stmt(AND, required as u32),
            jump(EQ, required as u32, 1, 0),
            stmt(RET, denied),
            stmt(RET, ALLOW),
        ],
    );
    let socket_type = [
        arg(1),
        stmt(AND, !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32),
        jump(EQ, libc::SOCK_STREAM as u32, 1, 0),
        stmt(RET, denied),
    ];
    if network {
        let mut body = vec![
            arg(0),
            jump(EQ, libc::AF_INET as u32, 2, 0),
            jump(EQ, libc::AF_INET6 as u32, 1, 0),
            stmt(RET, denied),
        ];
        body.extend(socket_type);
        body.extend([
            arg(2),
            jump(EQ, 0, 2, 0),
            jump(EQ, libc::IPPROTO_TCP as u32, 1, 0),
            stmt(RET, denied),
            stmt(RET, ALLOW),
        ]);
        f.syscall(libc::SYS_socket, &body);
    } else {
        f.verdict(libc::SYS_socket, denied);
        f.verdict(libc::SYS_connect, denied);
    }
    // asyncio and similar runtimes use a connected Unix stream pair as a
    // self-pipe. A stream pair cannot be reconnected to a host pathname.
    // New pathname sockets, datagram pairs, and raw sockets are denied.
    let mut pair = vec![
        arg(0),
        jump(EQ, libc::AF_UNIX as u32, 1, 0),
        stmt(RET, denied),
    ];
    pair.extend(socket_type);
    pair.extend([
        arg(2),
        jump(EQ, 0, 1, 0),
        stmt(RET, denied),
        stmt(RET, ALLOW),
    ]);
    f.syscall(libc::SYS_socketpair, &pair);
    for nr in [
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_register,
        libc::SYS_io_uring_enter,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
    ] {
        f.verdict(nr, denied);
    }
    let pid = std::process::id();
    for nr in [libc::SYS_kill, libc::SYS_tgkill] {
        f.syscall(
            nr,
            &[
                arg(0),
                jump(EQ, pid, 1, 0),
                stmt(RET, denied),
                stmt(RET, ALLOW),
            ],
        );
    }
    f.verdict(libc::SYS_tkill, denied);
    f.syscall(
        libc::SYS_ioctl,
        &[
            arg(1),
            jump(EQ, 0x5412, 3, 0), // TIOCSTI
            jump(EQ, 0x541c, 2, 0), // TIOCLINUX
            jump(EQ, 0x5437, 1, 0), // TIOCVHANGUP
            stmt(RET, ALLOW),
            stmt(RET, denied),
        ],
    );
    f.0.push(stmt(RET, ALLOW));
    let prog = libc::sock_fprog {
        len: f
            .0
            .len()
            .try_into()
            .map_err(|_| io::Error::other("seccomp filter too long"))?,
        filter: f.0.as_mut_ptr(),
    };
    // SAFETY: the bootstrap is single-threaded and prog points to a live
    // cBPF buffer copied by the kernel before this call returns.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::syscall(libc::SYS_seccomp, 1, NEW_LISTENER, &prog);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd as i32))
    }
}

/// Permit exactly one exec by the trusted bootstrap, then drop the last
/// listener. Linux returns ENOSYS for every later notified exec. Closing
/// also rejects queued calls; a plugin cannot race a second authorization.
pub(super) fn first_exec(listener: OwnedFd) -> io::Result<()> {
    let mut n = Notification::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "sandbox didn't exec its plugin",
            ));
        }
        let mut p = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // poll also observes HUP if the bootstrap dies before its exec.
        let ready = unsafe { libc::poll(&mut p, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if p.revents & libc::POLLIN == 0 {
            return Err(io::Error::other("sandbox ended before its first exec"));
        }
        // SAFETY: n has the kernel's seccomp_notif layout and is writable.
        if unsafe { libc::ioctl(listener.as_raw_fd(), RECV, &mut n) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted && e.raw_os_error() != Some(libc::ENOENT) {
            return Err(e);
        }
        n = Notification::default();
    }
    if n.data.arch != ARCH
        || ![libc::SYS_execve as i32, libc::SYS_execveat as i32].contains(&n.data.nr)
        || n.flags != 0
    {
        return Err(io::Error::other("unexpected first sandbox syscall"));
    }
    let r = Response {
        id: n.id,
        value: 0,
        error: 0,
        flags: CONTINUE,
    };
    // SAFETY: r has the kernel's seccomp_notif_resp layout. The caller
    // owns the only remaining listener; drop after SEND leaves no way for
    // plugin code to approve another exec.
    if unsafe { libc::ioctl(listener.as_raw_fd(), SEND, &r) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
