//! Linux counterpart of internal/plugin/proxy.go:16's single allowed network
//! exit. Only a trusted helper holds the descriptor channel out of the
//! private network namespace; plugin bytes still go through Proxy.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const LISTENER: u8 = b'L';
const CONNECTION: u8 = b'C';

fn high_fd(fd: OwnedFd) -> io::Result<OwnedFd> {
    // Reserved bootstrap descriptors 3/4/5 may already have been closed.
    // Helper-owned descriptors must never alias those close operations.
    let n = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two writable integers.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn send_fd(control: RawFd, kind: u8, fd: RawFd) -> io::Result<()> {
    let mut byte = [kind];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0u64; 4];
    // SAFETY: all pointers refer to live, aligned buffers. SCM_RIGHTS
    // copies fd into the peer's descriptor table; it doesn't transfer ours.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ancillary.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        loop {
            if libc::sendmsg(control, &msg, libc::MSG_NOSIGNAL) == 1 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

fn recv_fd(control: RawFd) -> io::Result<Option<(u8, OwnedFd)>> {
    let mut byte = [0u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0u64; 4];
    // SAFETY: recvmsg fills these live buffers. Every received descriptor
    // is immediately owned (even on malformed messages) and CLOEXEC.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ancillary.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&ancillary);
        let n = loop {
            let n = libc::recvmsg(control, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n >= 0 {
                break n;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        };
        if n == 0 {
            return Ok(None);
        }
        let mut fds = Vec::new();
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let header = libc::CMSG_LEN(0) as usize;
                if (*cmsg).cmsg_len < header {
                    return Err(io::Error::other("invalid descriptor message"));
                }
                let count = ((*cmsg).cmsg_len - header) / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i));
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        if n != 1 || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || fds.len() != 1 {
            return Err(io::Error::other("invalid sandbox descriptor message"));
        }
        Ok(Some((byte[0], fds.pop().unwrap())))
    }
}

/// The child end survives bwrap as fd5. The host end first authorizes the
/// bootstrap exec, then receives only accepted sockets from the helper.
pub(super) fn channel(proxy_port: u16) -> io::Result<OwnedFd> {
    let (host, child) = pair()?;
    std::thread::Builder::new()
        .name("plugin-sandbox".into())
        .stack_size(256 << 10)
        .spawn(move || {
            let result = (|| {
                let listener = match recv_fd(host.as_raw_fd())? {
                    Some((LISTENER, listener)) => listener,
                    // The caller can abandon an unspawned Command after a
                    // later validation error; this is ordinary cancellation.
                    None => return Ok(()),
                    Some(_) => return Err(io::Error::other("unexpected sandbox listener message")),
                };
                super::seccomp::first_exec(listener)?;
                if proxy_port != 0 {
                    relay(host.as_raw_fd(), proxy_port)?;
                }
                Ok::<_, io::Error>(())
            })();
            if let Err(e) = result {
                eprintln!("rush: plugin sandbox: {e}");
            }
        })?;
    Ok(child)
}

pub(super) fn send_listener(control: RawFd, listener: RawFd) -> io::Result<()> {
    send_fd(control, LISTENER, listener)
}

#[derive(Default)]
struct Connections {
    sockets: Mutex<HashMap<u64, (TcpStream, TcpStream)>>,
}

impl Connections {
    fn close(&self) {
        for (a, b) in self.sockets.lock().unwrap().values() {
            let _ = a.shutdown(Shutdown::Both);
            let _ = b.shutdown(Shutdown::Both);
        }
    }
}

fn relay(control: RawFd, port: u16) -> io::Result<()> {
    let connections = Arc::new(Connections::default());
    let result = relay_into(control, port, &connections);
    // A plugin ending closes the helper's control channel. Wake both
    // directions of every outstanding tunnel so host threads/FDs end too.
    connections.close();
    result
}

fn relay_into(control: RawFd, port: u16, connections: &Arc<Connections>) -> io::Result<()> {
    let mut id = 0u64;
    while let Some((kind, fd)) = recv_fd(control)? {
        if kind != CONNECTION {
            return Err(io::Error::other("unexpected sandbox descriptor"));
        }
        // This receiver is the only inserter. Check/acquire the permit
        // BEFORE connecting, cloning descriptors, or starting threads.
        let mut slots = connections.sockets.lock().unwrap();
        if slots.len() >= MAX_CONNECTIONS {
            continue;
        }
        let mut inner = TcpStream::from(fd);
        let mut outer = match TcpStream::connect_timeout(
            &([127, 0, 0, 1], port).into(),
            Duration::from_secs(2),
        ) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (mut read_inner, mut write_outer) = (inner.try_clone()?, outer.try_clone()?);
        slots.insert(id, (inner.try_clone()?, outer.try_clone()?));
        let key = id;
        id = id.wrapping_add(1);
        drop(slots);
        let all = Arc::clone(connections);
        let spawned = std::thread::Builder::new()
            .name("plugin-tunnel".into())
            .stack_size(256 << 10)
            .spawn(move || {
                let reverse = std::thread::Builder::new()
                    .name("plugin-tunnel-back".into())
                    .stack_size(256 << 10)
                    .spawn(move || {
                        let _ = io::copy(&mut read_inner, &mut write_outer);
                        let _ = write_outer.shutdown(Shutdown::Write);
                    });
                if let Ok(reverse) = reverse {
                    let _ = io::copy(&mut outer, &mut inner);
                    let _ = inner.shutdown(Shutdown::Write);
                    let _ = reverse.join();
                }
                all.sockets.lock().unwrap().remove(&key);
            });
        if spawned.is_err() {
            connections.sockets.lock().unwrap().remove(&key);
        }
    }
    Ok(())
}

/// Fork only from the fresh, single-threaded trusted bootstrap, BEFORE
/// installing seccomp/creating its listener. The child holds no plugin
/// IPC or policy descriptor. It accepts on private loopback and sends
/// accepted FDs; it never interprets a byte of plugin traffic.
pub(super) fn start_bridge(control: RawFd, proxy_port: u16) -> io::Result<()> {
    if proxy_port == 0 {
        return Ok(());
    }
    let listener = TcpListener::from(high_fd(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, proxy_port))?.into(),
    )?);
    let mut ready = [-1; 2];
    // SAFETY: bootstrap is single-threaded; pipe2 initializes both fds.
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (read_ready, write_ready) = unsafe {
        (
            OwnedFd::from_raw_fd(ready[0]),
            OwnedFd::from_raw_fd(ready[1]),
        )
    };
    let (read_ready, write_ready) = (high_fd(read_ready)?, high_fd(write_ready)?);
    // Nondumpable before forking, so even the brief startup interval
    // exposes neither the descriptor channel nor the future helper.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { libc::getpid() };
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        drop(read_ready);
        // SAFETY: these are bootstrap's reserved descriptors, not used by
        // the helper. A parent-death race fails closed.
        unsafe {
            libc::close(3);
            libc::close(4);
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                || libc::getppid() != parent
            {
                libc::_exit(1);
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 {
                libc::_exit(1);
            }
        }
        let mut ready = std::fs::File::from(write_ready);
        let result = ready.write_all(&[1]).and_then(|()| {
            drop(ready);
            bridge(listener, control)
        });
        // No destructors/constructors from the reexecuted test harness.
        unsafe {
            libc::_exit(if result.is_ok() { 0 } else { 1 });
        }
    }
    drop(write_ready);
    drop(listener);
    let mut byte = [0u8];
    std::fs::File::from(read_ready).read_exact(&mut byte)?;
    if byte != [1] {
        return Err(io::Error::other("network helper didn't become ready"));
    }
    Ok(())
}

fn bridge(listener: TcpListener, control: RawFd) -> io::Result<()> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control,
                events: 0,
                revents: 0,
            },
        ];
        // SAFETY: poll fills two live pollfd entries; no timeout/wake loop.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(());
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (socket, _) = listener.accept()?;
            send_fd(control, CONNECTION, socket.as_raw_fd())?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_messages_are_cloexec_and_end_with_the_channel() {
        let (a, b) = pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_fd(a.as_raw_fd(), CONNECTION, file.as_raw_fd()).unwrap();
        let (kind, fd) = recv_fd(b.as_raw_fd()).unwrap().unwrap();
        assert_eq!(kind, CONNECTION);
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(a);
        assert!(recv_fd(b.as_raw_fd()).unwrap().is_none());
    }

    #[test]
    fn relay_bounds_connections_and_shutdown_closes_every_tunnel() {
        let outer = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = outer.local_addr().unwrap().port();
        let inner = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (host, child) = pair().unwrap();
        let worker = std::thread::spawn(move || {
            let all = Arc::new(Connections::default());
            // An invalid packet ends the channel deterministically after
            // all preceding connection packets have been processed.
            assert!(relay_into(host.as_raw_fd(), port, &all).is_err());
            let held = all.sockets.lock().unwrap().len();
            all.close();
            held
        });
        let mut clients = Vec::new();
        for _ in 0..MAX_CONNECTIONS + 8 {
            let client = TcpStream::connect(inner.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let (accepted, _) = inner.accept().unwrap();
            send_fd(child.as_raw_fd(), CONNECTION, accepted.as_raw_fd()).unwrap();
            clients.push(client);
        }
        let invalid = std::fs::File::open("/dev/null").unwrap();
        send_fd(child.as_raw_fd(), b'?', invalid.as_raw_fd()).unwrap();
        assert_eq!(worker.join().unwrap(), MAX_CONNECTIONS);
        for mut client in clients {
            match client.read(&mut [0u8; 1]) {
                Ok(0) => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("relay left a connection alive: {other:?}"),
            }
        }
    }
}
