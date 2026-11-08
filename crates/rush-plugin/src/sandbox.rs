//! Starting a plugin: its environment, process, and platform sandbox.
//! Ported from internal/plugin/sandbox.go, sandbox_darwin.go and
//! sandbox_other.go (a bundled plugin's rush found as sandbox.go:79 finds
//! it, selfexe.Path).

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::gopath;
use crate::manifest::{PROTO_RUSH, eval_symlinks, expand_home};
use crate::plugin::Plugin;

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux;

#[cfg(not(target_os = "linux"))]
const ERR_NO_SANDBOX: &str =
    "plugins need a sandbox; this system needs macOS sandbox-exec or the Linux bubblewrap backend";
#[cfg(not(target_os = "linux"))]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
#[cfg(not(target_os = "linux"))]
const TASK_POLICY: &str = "/usr/sbin/taskpolicy";

/// How to start one plugin.
#[derive(Clone, Debug, Default)]
pub struct Launch {
    pub plugin: Plugin,
    /// rush's proxy for this plugin, or 0 for no network.
    pub proxy_port: u16,
}

/// Plugins run only when their platform's sandbox is available. Linux
/// probes its namespace/seccomp prerequisites and fails closed.
pub fn supported() -> Result<(), String> {
    #[cfg(all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux::supported()
    }
    #[cfg(all(
        target_os = "linux",
        not(all(
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))
    ))]
    {
        Err("Linux plugins require a GNU x86_64 or aarch64 build with bubblewrap".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        if std::fs::metadata(SANDBOX_EXEC).is_ok() {
            return Ok(());
        }
        Err(ERR_NO_SANDBOX.into())
    }
}

/// p with its links followed, or cleaned when it isn't there.
fn resolved(p: &str) -> String {
    eval_symlinks(p).unwrap_or_else(|| gopath::clean(p))
}

impl Launch {
    /// The whole environment a plugin gets: nothing of yours (no tokens, no
    /// Claude config), only where it may write, how to reach the proxy, and
    /// what its manifest sets. In name order.
    pub fn env(&self) -> Vec<String> {
        let m = &self.plugin.manifest;
        let data = gopath::s(&crate::data_dir(&m.name));
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &m.env {
            // ~ is yours, not the plugin's HOME: how it learns where another
            // tool's files, given it in read or write, are.
            let v = v
                .replace("${DATA}", &data)
                .replace("${PLUGIN}", &self.plugin.dir);
            env.insert(k.clone(), expand_home(&v));
        }
        for k in ["LANG", "LC_ALL", "TZ"] {
            if let Ok(v) = std::env::var(k)
                && !v.is_empty()
            {
                env.insert(k.into(), v);
            }
        }
        // Set last, so a manifest can't move them.
        let tmp = gopath::join(&[&data, "tmp"]);
        let mut fixed: Vec<(&str, String)> = vec![
            ("PATH", "/usr/bin:/bin".into()),
            ("HOME", data.clone()),
            ("TMPDIR", format!("{tmp}/")),
            ("RUSH_PLUGIN", m.name.clone()),
            ("RUSH_PLUGIN_DATA", data.clone()),
            // and as they were called before the rename, for plugins written then
            ("AGTOP_PLUGIN", m.name.clone()),
            ("AGTOP_PLUGIN_DATA", data.clone()),
        ];
        if m.proto() == PROTO_RUSH {
            fixed.push(("RUSH_IPC_FD", "3".into()));
            fixed.push(("AGTOP_IPC_FD", "3".into()));
        }
        if self.proxy_port > 0 {
            let proxy = format!("http://127.0.0.1:{}", self.proxy_port);
            for k in [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ] {
                fixed.push((k, proxy.clone()));
            }
            // Node reads the proxy variables only when asked to.
            fixed.push(("NODE_USE_ENV_PROXY", "1".into()));
            fixed.push(("NO_PROXY", String::new()));
            fixed.push(("no_proxy", String::new()));
        }
        for (k, v) in fixed {
            env.insert(k.into(), v);
        }
        env.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
    }

    fn apply_env(&self, cmd: &mut Command, extra: &[(String, String)]) {
        cmd.env_clear();
        for kv in self.env() {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
    }

    /// The plugin's process, its stdio and extra files for the caller to
    /// wire up: a bundled plugin is rush itself, `rush plugin run <name>`,
    /// in its data folder; any other is command(), sandboxed.
    pub fn process(&self) -> Result<Command, String> {
        if !self.plugin.bundled {
            return self.command();
        }
        let exe = rush_sys::selfexe::path().map_err(|e| e.to_string())?;
        let data = crate::data_dir(&self.plugin.name);
        crate::mkdir_all(&data.join("tmp"))?;
        let mut cmd = Command::new(exe);
        cmd.args(["plugin", "run", &self.plugin.name])
            .current_dir(&data);
        // Its HOME is its data folder, so it's told where rush's own state
        // is: without it, the gate plugin read no settings and ran no guard.
        // A dry run reaches it too: the gate's memory guard only writes
        // down what it would stop.
        let mut extra = vec![("RUSH_HOME".into(), gopath::s(&rush_state::dir()))];
        for k in ["RUSH_DRYRUN", "RUSH_DRYRUN_LOG"] {
            if let Ok(v) = std::env::var(k) {
                extra.push((k.into(), v));
            }
        }
        self.apply_env(&mut cmd, &extra);
        cmd.process_group(0);
        keep_only_stdio(&mut cmd);
        Ok(cmd)
    }

    /// The path of the plugin's program, symlinks resolved.
    pub fn program(&self) -> Result<String, String> {
        let mut p = self.plugin.command.first().cloned().unwrap_or_default();
        if !gopath::is_abs(&p) {
            p = gopath::join(&[&self.plugin.dir, &p]);
        }
        std::fs::canonicalize(&p)
            .map(|r| gopath::s(&r))
            .map_err(|e| gopath::os_err("lstat", Path::new(&p), &e))
    }

    /// The sandbox the plugin runs in. It denies everything, then allows
    /// only what the plugin needs to load and run: its program, its own
    /// folder and the system's libraries to read, its data folder to
    /// write, and one localhost port, its proxy's, to connect to. It may
    /// not start another program, open a socket anywhere else, or look up
    /// system services beyond the one libSystem needs at start.
    pub fn profile(&self) -> Result<String, String> {
        let prog = self.program()?;
        let name = &self.plugin.name;
        let mut b = String::from("(version 1)\n(deny default)\n");
        b += &format!("(allow process-exec (literal {}))\n", quote(&prog));
        if let Some(app) = python_app(&prog) {
            // A framework Python's bin/python3 only starts the real one, and
            // replaces itself with it, so this is still one program.
            b += &format!("(allow process-exec (literal {}))\n", quote(&app));
        }
        let data = gopath::s(&crate::data_dir(name));
        let mut reads: Vec<String> = [
            "/usr/lib",
            "/usr/share",
            "/System",
            "/Library/Apple/System",
            "/private/var/db/dyld",
            "/private/var/db/timezone",
            "/private/etc/ssl",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        reads.push(resolved(&self.plugin.dir));
        reads.push(resolved(&data));
        reads.extend(runtime_dirs(&prog));
        for r in &self.plugin.read {
            reads.push(resolved(&expand_home(r)));
        }
        let mut writes = vec![resolved(&data)];
        for w in &self.plugin.write {
            writes.push(resolved(&expand_home(w)));
        }
        reads.extend(writes[1..].iter().cloned());
        b += "(allow file-read*\n  (literal \"/\") (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\")\n  (literal \"/private/etc/localtime\")";
        for r in &reads {
            b += &format!("\n  (subpath {})", quote(r));
        }
        b += ")\n";
        // Finding its libraries means looking at paths on the way to them.
        b += "(allow file-read-metadata)\n";
        b += "(allow file-write*";
        for w in &writes {
            b += &format!(" (subpath {})", quote(w));
        }
        b += " (literal \"/dev/null\"))\n";
        b += "(allow file-ioctl (literal \"/dev/null\"))\n";
        b += "(allow sysctl-read)\n";
        b += "(allow mach-lookup (global-name \"com.apple.system.notification_center\"))\n";
        if self.proxy_port > 0 {
            b += &format!(
                "(allow network-outbound (remote ip {}))\n",
                quote(&format!("localhost:{}", self.proxy_port))
            );
        }
        Ok(b)
    }

    /// The plugin's process, sandboxed and clamped to utility QoS so it
    /// never competes with you or your agents for the CPU. The caller
    /// wires up its stdio and extra files (fd 3: see with_ipc_fd). A
    /// plugin never runs unsandboxed.
    pub fn command(&self) -> Result<Command, String> {
        #[cfg(all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            linux::command(self)
        }
        #[cfg(all(
            target_os = "linux",
            not(all(
                target_env = "gnu",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))
        ))]
        {
            supported()?;
            Err("Linux plugin backend unavailable".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.macos_command()
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn macos_command(&self) -> Result<Command, String> {
        supported()?;
        let data = crate::data_dir(&self.plugin.name);
        crate::mkdir_all(&data.join("tmp"))?;
        let profile = self.profile()?;
        let prog = self.program().unwrap_or_default();
        let mut args: Vec<String> = vec![SANDBOX_EXEC.into(), "-p".into(), profile, prog];
        args.extend(self.plugin.command.iter().skip(1).cloned());
        if std::fs::metadata(TASK_POLICY).is_ok() {
            args.splice(
                0..0,
                [TASK_POLICY.to_string(), "-c".into(), "utility".into()],
            );
        }
        let mut cmd = Command::new(&args[0]);
        cmd.args(&args[1..]).current_dir(resolved(&self.plugin.dir));
        self.apply_env(&mut cmd, &[]);
        // Its own process group, so ending it ends anything it managed to
        // leave.
        cmd.process_group(0);
        keep_only_stdio(&mut cmd);
        Ok(cmd)
    }
}

/// Has the process cmd starts keep none of what rush holds open but its
/// stdio, and the fd 3 with_ipc_fd hands it (set after this). On macOS a
/// socket pair or pipe rush makes is marked close-on-exec only a moment
/// after it's made, and a process started from another thread in that
/// moment would keep it: another plugin's end of its channel to the
/// broker, say, letting it speak as that plugin. Go holds
/// syscall.ForkLock over both instead.
pub fn keep_only_stdio(cmd: &mut Command) {
    #[cfg(target_os = "linux")]
    // No artificial descriptor ceiling: a plugin must not inherit a
    // broker channel opened above the old 65536-descriptor scan limit.
    unsafe {
        cmd.pre_exec(|| {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let max = open_max();
        // SAFETY: fcntl is async-signal-safe, as pre_exec needs.
        unsafe {
            cmd.pre_exec(move || {
                for fd in 3..max {
                    let fl = libc::fcntl(fd, libc::F_GETFD);
                    if fl >= 0 && fl & libc::FD_CLOEXEC == 0 {
                        libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC);
                    }
                }
                Ok(())
            });
        }
    }
}

/// One past the highest descriptor this process may have open, bounded so
/// a limit of "unlimited" doesn't mean looking at billions.
#[cfg(not(target_os = "linux"))]
fn open_max() -> libc::c_int {
    const CAP: libc::rlim_t = 1 << 16;
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills rl.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return CAP as libc::c_int;
    }
    rl.rlim_cur.clamp(64, CAP) as libc::c_int
}

/// Hands fd to the process cmd starts as its fd 3, where a plugin speaking
/// rush's protocol finds its end of the socket pair (Go's ExtraFiles).
pub fn with_ipc_fd(cmd: &mut Command, fd: std::os::fd::RawFd) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // Reserve a distinct source before any pre_exec hook maps fd4/fd5.
    // Capturing ownership also keeps it live until spawn (or cmd drop).
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 16) };
    let source = if dup < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    };
    // SAFETY: dup2 and fcntl are async-signal-safe, as pre_exec needs.
    unsafe {
        cmd.pre_exec(move || {
            let source = source
                .as_ref()
                .map_err(|&code| std::io::Error::from_raw_os_error(code))?;
            if libc::dup2(source.as_raw_fd(), 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// What an interpreter from Homebrew needs to read: its keg, the libraries
/// it links, and OpenSSL's configuration.
fn runtime_dirs(prog: &str) -> Vec<String> {
    for prefix in ["/opt/homebrew", "/usr/local"] {
        if prog.starts_with(&format!("{prefix}/")) {
            return [
                "/Cellar",
                "/opt",
                "/lib",
                "/etc/openssl@3",
                "/etc/ca-certificates",
            ]
            .iter()
            .map(|s| format!("{prefix}{s}"))
            .collect();
        }
    }
    Vec::new()
}

/// The interpreter a framework build of Python's bin/python3 hands over to
/// (Homebrew's and python.org's are built this way), if there is one.
fn python_app(prog: &str) -> Option<String> {
    const MARK: &str = "/Python.framework/Versions/";
    let i = prog.find(MARK)?;
    let rest = &prog[i + MARK.len()..];
    let (v, _) = rest.split_once('/')?;
    let app = format!(
        "{}{MARK}{v}/Resources/Python.app/Contents/MacOS/Python",
        &prog[..i]
    );
    std::fs::metadata(&app).is_ok().then_some(app)
}

/// s as a sandbox profile string.
pub(crate) fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::plugin::load;
    use crate::plugin::tests::{Home, install_plugin, manifest};

    #[test]
    fn env_is_clean_and_fixed() {
        let _h = Home::new();
        let l = Launch {
            plugin: Plugin {
                manifest: Manifest {
                    name: "p".into(),
                    command: vec!["x".into()],
                    env: [
                        ("HOME".to_string(), "/Users/me".to_string()),
                        ("STORE".to_string(), "${DATA}/db".to_string()),
                    ]
                    .into(),
                    ..Default::default()
                },
                dir: "/plug".into(),
                ..Default::default()
            },
            proxy_port: 4242,
        };
        let env = l.env();
        let get = |k: &str| {
            env.iter()
                .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                .unwrap_or("")
                .to_string()
        };
        // Nothing of rush's own environment goes, whatever it holds.
        assert!(env.iter().all(
            |kv| !kv.starts_with("ANTHROPIC_API_KEY=") && !kv.starts_with("CLAUDE_CONFIG_DIR=")
        ));
        let data = gopath::s(&crate::data_dir("p"));
        assert_eq!(get("HOME"), data, "the manifest moved HOME");
        assert_eq!(get("STORE"), format!("{data}/db"));
        assert_eq!(get("HTTPS_PROXY"), "http://127.0.0.1:4242");
        assert_eq!(get("RUSH_IPC_FD"), "3");
        assert_eq!(get("TMPDIR"), format!("{data}/tmp/"));
        assert_eq!(get("PATH"), "/usr/bin:/bin");
    }

    #[test]
    fn keeps_only_stdio() {
        // A descriptor left open without close-on-exec, as one is for a
        // moment after std makes a pipe on macOS, isn't passed on.
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds is two ints for pipe to fill.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            &format!("[ -e /dev/fd/{} ] && echo open || echo closed", fds[1]),
        ]);
        keep_only_stdio(&mut cmd);
        let out = cmd.output().unwrap();
        // SAFETY: closing the two descriptors pipe gave us.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "closed");
    }

    #[test]
    fn profile_quotes_paths() {
        assert_eq!(quote(r#"/a "b"\c"#), r#""/a \"b\"\\c""#);
    }

    #[test]
    fn profile_writes() {
        let h = Home::new();
        let other = gopath::s(&h.path().join("kanban"));
        let mut m = manifest("w", "/bin/sh");
        m.write = vec![other.clone()];
        let p = load(&install_plugin(&m, &[])).unwrap();
        let prof = Launch {
            plugin: p,
            proxy_port: 0,
        }
        .profile()
        .unwrap();
        let writes = prof
            .lines()
            .rfind(|l| l.starts_with("(allow file-write*"))
            .unwrap_or("");
        assert!(writes.contains(&quote(&other)), "writes = {writes}");
        assert!(
            writes.contains(&quote(&gopath::s(&crate::data_dir("w")))),
            "writes = {writes}"
        );
        assert!(!prof.contains("network-outbound"), "no proxy, no network");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn closes_high_descriptors_and_preserves_only_the_mapped_ipc() {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;
        let file = std::fs::File::open("/dev/null").unwrap();
        let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 70_000) };
        if high < 0 {
            // If the process limit is below the former scan ceiling,
            // there cannot be an open descriptor beyond that ceiling.
            assert!(matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL | libc::EMFILE)
            ));
            return;
        }
        let _high = unsafe { OwnedFd::from_raw_fd(high) };
        let (mut mine, theirs) = UnixStream::pair().unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "test ! -e /proc/self/fd/$1 && printf ipc >&3",
            "sh",
            &high.to_string(),
        ]);
        keep_only_stdio(&mut cmd);
        // Deliberately clobber the caller's original IPC source before
        // with_ipc_fd's hook. Its reserved parent duplicate must survive.
        let original = theirs.as_raw_fd();
        let null = file.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(null, original) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        with_ipc_fd(&mut cmd, original);
        assert!(cmd.status().unwrap().success());
        drop(theirs);
        let mut buf = [0; 3];
        mine.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ipc");
    }
}
