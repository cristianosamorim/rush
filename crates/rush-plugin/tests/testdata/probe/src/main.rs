//! probe is a plugin that tries to get out of its sandbox, for the sandbox
//! tests. Asked to "probe", it attempts each thing it should not be able
//! to do and says which it managed.
//! Ported from rust/crates/rush-plugin/tests/testdata/probe/main.go.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

fn main() {
    rush_plugin_sdk::serve(|_, _, p| Ok(json!(probe(&p))))
}

fn probe(p: &Value) -> BTreeMap<&'static str, String> {
    let s = |k: &str| p[k].as_str().unwrap_or_default().to_string();
    let (secret, outside, sock, data) = (s("secret"), s("outside"), s("sock"), s("data"));
    let ok = |r: std::io::Result<()>| match r {
        Ok(()) => "allowed".to_string(),
        Err(e) => format!("denied: {e}"),
    };
    let dial = |addr: &str| {
        let a: SocketAddr = addr.parse().map_err(std::io::Error::other)?;
        TcpStream::connect_timeout(&a, Duration::from_secs(2)).map(drop)
    };
    let mut out = BTreeMap::new();
    out.insert("read secret", ok(std::fs::read(&secret).map(drop)));
    out.insert("write outside", ok(std::fs::write(&outside, "x")));
    out.insert(
        "write data",
        ok(std::fs::write(Path::new(&data).join("x"), "x")),
    );
    let secret_dir = Path::new(&secret).parent().unwrap_or(Path::new("/"));
    out.insert(
        "list secret dir",
        ok(std::fs::read_dir(secret_dir).map(drop)),
    );
    out.insert(
        "exec",
        ok(std::process::Command::new("/bin/echo")
            .arg("hi")
            .output()
            .map(drop)),
    );
    out.insert("internet", ok(dial("1.1.1.1:443")));
    out.insert("localhost", ok(dial("127.0.0.1:22")));
    out.insert("rush socket", ok(UnixStream::connect(&sock).map(drop)));
    if let Some(port) = p["proxy"].as_u64().filter(|&n| n > 0) {
        out.insert("proxy", ok(dial(&format!("127.0.0.1:{port}"))));
        // Connecting alone cannot prove the namespace bridge works. An
        // actual response proves both byte directions reach Proxy and
        // that its approved-host checks remain in force.
        let response = (|| -> std::io::Result<()> {
            use std::io::{Read, Write};
            let mut c = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port as u16))?;
            c.set_read_timeout(Some(Duration::from_secs(3)))?;
            c.set_write_timeout(Some(Duration::from_secs(3)))?;
            c.write_all(
                b"CONNECT unapproved.invalid:443 HTTP/1.1\r\nHost: unapproved.invalid:443\r\n\r\n",
            )?;
            let mut status = [0; 12];
            c.read_exact(&mut status)?;
            if &status != b"HTTP/1.1 403" {
                return Err(std::io::Error::other("proxy didn't enforce host approval"));
            }
            Ok(())
        })();
        out.insert("proxy policy", ok(response));
    }
    out.insert("home", std::env::var("HOME").unwrap_or_default());
    out.insert(
        "token",
        std::env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
    );
    #[cfg(target_os = "linux")]
    linux_probes(&mut out, &sock);
    out
}

#[cfg(target_os = "linux")]
fn linux_probes(out: &mut BTreeMap<&'static str, String>, socket_path: &str) {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let verdict = |n: libc::c_long| {
        if n < 0 {
            format!("denied: {}", std::io::Error::last_os_error())
        } else {
            "allowed".to_string()
        }
    };
    // Exec an executable known to be visible, without first forking. If
    // either succeeds, this RPC never replies and the integration fails.
    let exe = CString::new(
        std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_encoded_bytes(),
    )
    .unwrap();
    let argv = [exe.as_ptr(), std::ptr::null()];
    let env = [std::ptr::null::<libc::c_char>()];
    unsafe {
        out.insert(
            "execve",
            verdict(libc::syscall(
                libc::SYS_execve,
                exe.as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
            )),
        );
        // Absolute paths ignore dirfd, even with AT_EMPTY_PATH: an FD-only
        // execveat filter is insufficient to stop this variant.
        out.insert(
            "execveat absolute",
            verdict(libc::syscall(
                libc::SYS_execveat,
                64,
                exe.as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            )),
        );
        let mut allow = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        };
        let program = libc::sock_fprog {
            len: 1,
            filter: &mut allow,
        };
        let listener = libc::syscall(libc::SYS_seccomp, 1, 8, &program);
        out.insert("new seccomp listener", verdict(listener));
        if listener >= 0 {
            drop(OwnedFd::from_raw_fd(listener as i32));
        }
        out.insert(
            "prctl seccomp",
            verdict(libc::prctl(libc::PR_SET_SECCOMP, 2, &program) as libc::c_long),
        );
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        out.insert("unix socket", verdict(fd as libc::c_long));
        if fd >= 0 {
            drop(OwnedFd::from_raw_fd(fd));
        }
        let mut pair = [-1; 2];
        let n = libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        );
        out.insert("unix datagram pair", verdict(n as libc::c_long));
        if n == 0 {
            drop((OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])));
        }
        let mut params = [0u64; 32]; // larger than struct io_uring_params
        let ring = libc::syscall(libc::SYS_io_uring_setup, 2, params.as_mut_ptr());
        out.insert("io_uring", verdict(ring));
        if ring >= 0 {
            drop(OwnedFd::from_raw_fd(ring as i32));
        }
    }
    let (a, _b) =
        UnixStream::pair().expect("connected stream pairs support async runtime self-pipes");
    // An established Unix stream cannot become a new connection, even
    // after shutdown and an attempted AF_UNSPEC disconnect.
    let _ = a.shutdown(std::net::Shutdown::Both);
    unsafe {
        let mut disconnect: libc::sockaddr = std::mem::zeroed();
        disconnect.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        let _ = libc::connect(
            a.as_raw_fd(),
            &disconnect,
            std::mem::size_of_val(&disconnect) as u32,
        );
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dest, &src) in addr.sun_path.iter_mut().zip(socket_path.as_bytes()) {
            *dest = src as libc::c_char;
        }
        out.insert(
            "unix stream reconnect",
            verdict(libc::connect(
                a.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                std::mem::size_of_val(&addr) as u32,
            ) as libc::c_long),
        );
        let mut stat: libc::statvfs = std::mem::zeroed();
        let n = libc::statvfs(c"/proc".as_ptr(), &mut stat);
        out.insert(
            "proc readonly",
            if n == 0 && stat.f_flag & libc::ST_RDONLY != 0 {
                "allowed".into()
            } else {
                "denied".into()
            },
        );
    }
    out.insert(
        "proc init write",
        match std::fs::OpenOptions::new().write(true).open("/proc/1/mem") {
            Ok(_) => "allowed".into(),
            Err(e) => format!("denied: {e}"),
        },
    );
}
