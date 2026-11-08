//! rush-plugin against the plugins in the repository: their manifests
//! load as Go rush loads them, and their programs, written in Rust on
//! rush-plugin-sdk and built here with cargo, talk to rush over the wire
//! protocol, from inside the sandbox rush puts them in.
//! Ported from internal/plugin/category_test.go:24-37 (TestRepoPluginsLoad)
//! and sandbox_darwin_test.go:14-110 (TestSandboxHolds).

// Every test runs in a throwaway home (rush-testenv).
rush_testenv::sandboxed!();

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rush_plugin::rpc::{Handler, no_method, to_raw};
use rush_plugin::sandbox::with_ipc_fd;
use rush_plugin::{Conn, Ctx, Launch, Proxy, load};
use serde_json::{Value, json};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// A rush folder of its own for this test's thread, resolved, as the
/// sandbox is keyed on resolved paths.
struct Home(tempfile::TempDir);

impl Home {
    fn new() -> Home {
        let d = tempfile::tempdir().unwrap();
        rush_state::set_thread_dir(Some(d.path().canonicalize().unwrap()));
        Home(d)
    }
    fn path(&self) -> PathBuf {
        self.0.path().canonicalize().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        rush_state::set_thread_dir(None);
    }
}

/// Builds the program bin of the workspace's package pkg, as cargo builds
/// it, and copies it to out. It builds into a target folder of its own:
/// the cargo running the tests holds the workspace's.
fn cargo_build(pkg: &str, bin: &str, out: &Path) {
    let cargo = PathBuf::from(env!("CARGO"));
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("plugins");
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "build",
        "--quiet",
        "--locked",
        "--offline",
        "-p",
        pkg,
        "--bin",
        bin,
    ])
    .env("CARGO_TARGET_DIR", &target)
    .env_remove("RUSTC_WRAPPER")
    .current_dir(repo());
    // rush-testenv moved HOME and PATH away: cargo finds its own again.
    if let Some(real) = std::env::var_os("RUSH_TEST_REAL_HOME") {
        for (var, dir) in [("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")] {
            if std::env::var_os(var).is_none() {
                cmd.env(var, Path::new(&real).join(dir));
            }
        }
    }
    if let Some(bin_dir) = cargo.parent() {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{path}", bin_dir.display()));
        let rustc = bin_dir.join("rustc");
        if rustc.exists() && std::env::var_os("RUSTC").is_none() {
            cmd.env("RUSTC", rustc);
        }
    }
    let o = cmd
        .output()
        .unwrap_or_else(|e| panic!("running cargo: {e}"));
    assert!(
        o.status.success(),
        "cargo build -p {pkg}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    rush_testenv::copy_executable(&target.join("debug").join(bin), out).unwrap();
}

/// Installs the example plugin name into the test's rush folder: its
/// manifest, and its program built from source.
fn install_example(name: &str) -> PathBuf {
    let dir = rush_plugin::root().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(
        repo()
            .join("plugins/examples")
            .join(name)
            .join("plugin.json"),
        dir.join("plugin.json"),
    )
    .unwrap();
    cargo_build(name, name, &dir.join(name));
    dir
}

/// Starts the plugin in dir as the broker does, sandboxed, with conn on
/// the other end of its fd 3.
fn start(dir: &Path, proxy_port: u16, h: Handler) -> (std::process::Child, Conn) {
    let p = load(dir).unwrap();
    let (mine, theirs) = UnixStream::pair().unwrap();
    let mut cmd = Launch {
        plugin: p,
        proxy_port,
    }
    .command()
    .unwrap();
    with_ipc_fd(&mut cmd, theirs.as_raw_fd());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let child = cmd.spawn().unwrap();
    drop(theirs);
    (child, Conn::new(mine, Some(h)).unwrap())
}

fn stop(mut child: std::process::Child, conn: Conn) {
    conn.close();
    let _ = child.kill();
    let _ = child.wait();
}

/// CI asks for a real plugin sandbox. Other platforms keep the existing
/// opt-in behaviour so a missing local sandbox does not make the examples
/// require an external runtime.
fn sandbox_is_required() -> bool {
    (cfg!(target_os = "linux") && std::env::var_os("CI").is_some())
        || std::env::var_os("RUSH_TEST_REQUIRE_PLUGIN_SANDBOX").is_some()
        || std::env::var_os("PLUGIN_SANDBOX_REQUIRED").is_some()
}

#[test]
fn required_plugin_sandbox_is_available() {
    if sandbox_is_required() {
        rush_plugin::supported().unwrap_or_else(|e| panic!("plugin sandbox required: {e}"));
    }
}

/// Waits for a file predicate without sleeping. The plugin's writer gets
/// scheduled by yielding, and a deadline keeps a broken child from hanging
/// the test forever.
fn wait_for_file(path: &Path, want: impl Fn(&str) -> bool) -> String {
    let until = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && want(&text)
        {
            return text;
        }
        assert!(
            std::time::Instant::now() < until,
            "{} did not reach the expected contents",
            path.display()
        );
        std::thread::yield_now();
    }
}

/// The plugins in the repository load, each under a category.
#[test]
fn repo_plugins_load() {
    let mut n = 0;
    for e in std::fs::read_dir(repo().join("plugins/examples"))
        .unwrap()
        .flatten()
    {
        let dir = e.path();
        if !dir.join("plugin.json").exists() {
            continue;
        }
        let p = load(&dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()));
        assert!(!p.category.is_empty(), "{} names no category", p.name);
        n += 1;
    }
    assert!(n >= 6, "found {n} example plugins");
}

/// neighbours, built from its source on rush-plugin-sdk, answers rush's
/// calls and calls rush back, sandboxed.
#[test]
fn neighbours_speaks_the_protocol() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let _h = Home::new();
    let dir = install_example("neighbours");
    let h: Handler = Arc::new(|_, _, method, _| match method {
        "sessions.list" => to_raw(&json!([
            {"id": "me", "name": "Me", "repo": "/r", "state": "running"},
            {"id": "x", "name": "Other", "repo": "/r/.claude/worktrees/w", "branch": "feat",
             "state": "running", "worktree": true, "detail": "testing"},
            {"id": "y", "name": "Gone", "repo": "/r", "state": "stopped"},
        ]))
        .map(Some),
        m => Err(no_method(m)),
    });
    let (child, conn) = start(&dir, 0, h);
    let ctx = Ctx::background().with_timeout(Duration::from_secs(20));
    let init: Value = conn
        .call(&ctx, "initialize", &json!({"settings": {}}))
        .unwrap();
    assert_eq!(init, json!({}));
    let tools: Value = conn.call(&ctx, "tools.list", &()).unwrap();
    assert_eq!(tools["tools"][0]["name"], "neighbours");
    let res: Value = conn
        .call(
            &ctx,
            "tools.call",
            &json!({"session": "me", "cwd": "/r", "name": "neighbours", "arguments": {}}),
        )
        .unwrap();
    assert_eq!(res["isError"], false);
    assert_eq!(
        res["content"][0]["text"],
        "- Other (x) on feat, running in its own worktree: testing\n"
    );
    // A method it doesn't know is Go's "method not found".
    let e = conn.call::<_, Value>(&ctx, "frob", &()).unwrap_err();
    assert_eq!(
        e.rpc().map(|e| e.code),
        Some(rush_plugin::rpc::CODE_NO_METHOD)
    );
    stop(child, conn);
}

/// reconnect, the UI hooks' example, speaks the protocol with rush too:
/// settings, events and commands.
#[test]
fn reconnect_speaks_the_protocol() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let _h = Home::new();
    let dir = install_example("reconnect");
    let h: Handler = Arc::new(|_, _, m, _| Err(no_method(m)));
    let (child, conn) = start(&dir, 0, h);
    let ctx = Ctx::background().with_timeout(Duration::from_secs(20));
    let init: Value = conn
        .call(&ctx, "initialize", &json!({"settings": {"wait": "5s"}}))
        .unwrap();
    assert_eq!(init, json!({}));
    let set: Value = conn
        .call(&ctx, "ui.settings", &json!({"values": {"tries": "3"}}))
        .unwrap();
    assert_eq!(set, json!({}));
    conn.notify(
        "ui.event",
        &json!({"kind": "network.down", "ui": "w1", "at": "2026-10-29T10:00:00Z"}),
    )
    .unwrap();
    let tools: Value = conn.call(&ctx, "tools.list", &()).unwrap();
    assert_eq!(tools, json!({"tools": []}));
    let e = conn
        .call::<_, Value>(&ctx, "ui.command", &json!({"command": "x"}))
        .unwrap_err();
    assert_eq!(e.to_string(), "reconnect has no commands");
    stop(child, conn);
}

/// autodrafts runs through the real sandbox, handles UI input, persists a
/// draft, restores it through a UI request, and reads it back after restart.
#[test]
fn autodrafts_persists_and_restores_through_the_sandbox() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let _h = Home::new();
    let dir = install_example("autodrafts");
    let data = rush_plugin::data_dir("autodrafts");
    std::fs::create_dir_all(&data).unwrap();
    let calls = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let seen = calls.clone();
    let h: Handler = Arc::new(move |_, _, method, p| {
        let params = p
            .map(|p| serde_json::from_str::<Value>(p.get()).unwrap())
            .unwrap_or(Value::Null);
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((method.to_string(), params));
        match method {
            "ui.input.set" | "ui.notify" => to_raw(&json!({})).map(Some),
            m => Err(no_method(m)),
        }
    });

    let (child, conn) = start(&dir, 0, h);
    let ctx = Ctx::background().with_timeout(Duration::from_secs(20));
    conn.call::<_, Value>(
        &ctx,
        "initialize",
        &json!({"dataDir": data, "settings": {"keep": "10"}}),
    )
    .unwrap();
    conn.notify(
        "ui.event",
        &json!({
            "kind": "input.changed",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"},
            "text": "persist me"
        }),
    )
    .unwrap();
    conn.notify(
        "ui.event",
        &json!({
            "kind": "input.cleared",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"},
            "text": "persist me"
        }),
    )
    .unwrap();
    let path = data.join("drafts.json");
    wait_for_file(&path, |s| s.contains("persist me"));
    conn.call::<_, Value>(
        &ctx,
        "ui.command",
        &json!({
            "command": "restore",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"}
        }),
    )
    .unwrap();
    let calls_now = calls.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        calls_now.iter().any(|(method, p)| {
            method == "ui.input.set" && p["text"] == "persist me" && p["session"] == "s1"
        }),
        "restore did not set the input: {calls_now:?}"
    );
    drop(calls_now);
    // Keep a second copy so the restarted process exercises a non-empty
    // on-disk draft after the first restore consumed one.
    conn.notify(
        "ui.event",
        &json!({
            "kind": "input.changed",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"},
            "text": "persist me"
        }),
    )
    .unwrap();
    conn.notify(
        "ui.event",
        &json!({
            "kind": "input.cleared",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"},
            "text": "persist me"
        }),
    )
    .unwrap();
    wait_for_file(&path, |s| s.contains("persist me"));
    stop(child, conn);

    // A fresh process must load the same data folder, not just its parent's
    // in-memory Book.
    let calls = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let seen = calls.clone();
    let h: Handler = Arc::new(move |_, _, method, p| {
        let params = p
            .map(|p| serde_json::from_str::<Value>(p.get()).unwrap())
            .unwrap_or(Value::Null);
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((method.to_string(), params));
        match method {
            "ui.input.set" | "ui.notify" => to_raw(&json!({})).map(Some),
            m => Err(no_method(m)),
        }
    });
    let (child, conn) = start(&dir, 0, h);
    conn.call::<_, Value>(
        &ctx,
        "initialize",
        &json!({"dataDir": data, "settings": {"keep": "10"}}),
    )
    .unwrap();
    conn.call::<_, Value>(
        &ctx,
        "ui.command",
        &json!({
            "command": "restore",
            "ui": "w1",
            "session": {"id": "s1", "name": "Draft session"}
        }),
    )
    .unwrap();
    let calls_now = calls.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        calls_now.iter().any(|(method, p)| {
            method == "ui.input.set" && p["text"] == "persist me" && p["session"] == "s1"
        }),
        "restart did not restore the persisted input: {calls_now:?}"
    );
    stop(child, conn);
}

/// Runs a real plugin in the real sandbox and has it try to get out: read
/// your files, write outside its data folder, start a program, reach the
/// internet, localhost or rush's own sockets.
#[test]
fn sandbox_holds() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let home = Home::new();
    let dir = rush_plugin::root().join("probe");
    std::fs::create_dir_all(&dir).unwrap();
    let data = rush_plugin::data_dir("probe");
    #[cfg(target_os = "linux")]
    let outside_preload = home.path().join("preload-outside");
    #[allow(unused_mut)]
    let mut manifest = json!({
        "name": "probe",
        "command": ["probe"],
        "network": ["example.com:443"]
    });
    #[cfg(target_os = "linux")]
    {
        // This constructor must run only after the sandbox has been applied:
        // its data marker is allowed, while the second path is not.
        let source = dir.join("preload.c");
        let library = dir.join("preload.so");
        std::fs::write(
            &source,
            r#"#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static void mark(const char *path, const char *message, size_t length) {
    if (path == NULL) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)write(fd, message, length);
        (void)close(fd);
    }
}

__attribute__((constructor)) static void rush_preload(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int filtered = fd == -1 && errno == EPERM;
    if (fd >= 0) close(fd);
    const char *message = filtered ? "filtered\n" : "unfiltered\n";
    mark(getenv("RUSH_PRELOAD_ALLOWED"), message, filtered ? 9 : 11);
    mark(getenv("RUSH_PRELOAD_OUTSIDE"), message, filtered ? 9 : 11);
}
"#,
        )
        .unwrap();
        let cc = Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .output()
            .expect("Linux CI needs cc for the loader-env sandbox probe");
        assert!(
            cc.status.success(),
            "cc preload: {}",
            String::from_utf8_lossy(&cc.stderr)
        );
        manifest["env"] = json!({
            "LD_PRELOAD": "${PLUGIN}/preload.so",
            "RUSH_PRELOAD_ALLOWED": "${DATA}/preload-loaded",
            "RUSH_PRELOAD_OUTSIDE": outside_preload.to_string_lossy()
        });
    }
    std::fs::write(
        dir.join("plugin.json"),
        rush_state::json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    cargo_build("rush-plugin-probe", "probe", &dir.join("probe"));
    let p = load(&dir).unwrap();
    let secret_dir = home.path().join("secrets");
    std::fs::create_dir_all(&secret_dir).unwrap();
    let secret = secret_dir.join("token");
    std::fs::write(&secret, "sk-secret").unwrap();
    let sock = home.path().join("rush.sock");
    let _ln = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let proxy = Proxy::listen(&p.network, None).unwrap();

    let h: Handler = Arc::new(|_, _, m, _| Err(no_method(m)));
    let (child, conn) = start(&dir, proxy.port(), h);
    let ctx = Ctx::background().with_timeout(Duration::from_secs(20));
    let got: std::collections::BTreeMap<String, String> = conn
        .call(
            &ctx,
            "probe",
            &json!({
                "secret": secret, "outside": dir.join("planted"), "sock": sock,
                "data": data, "proxy": proxy.port(),
            }),
        )
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        let marker = data.join("preload-loaded");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "filtered\n",
            "untrusted preload code ran before seccomp"
        );
        assert!(
            !outside_preload.exists(),
            "loader env escaped the sandbox: {}",
            outside_preload.display()
        );
    }
    for (k, want) in [
        ("read secret", "denied"),
        ("write outside", "denied"),
        ("list secret dir", "denied"),
        ("exec", "denied"),
        ("internet", "denied"),
        ("localhost", "denied"),
        ("rush socket", "denied"),
        ("write data", "allowed"),
        ("proxy", "allowed"),
        ("proxy policy", "allowed"),
    ] {
        let v = got.get(k).cloned().unwrap_or_default();
        assert!(v.starts_with(want), "{k}: {v}, want {want}");
    }
    #[cfg(target_os = "linux")]
    for (k, want) in [
        ("execve", "denied"),
        ("execveat absolute", "denied"),
        ("new seccomp listener", "denied"),
        ("prctl seccomp", "denied"),
        ("unix socket", "denied"),
        ("unix datagram pair", "denied"),
        ("unix stream reconnect", "denied"),
        ("proc init write", "denied"),
        ("proc readonly", "allowed"),
        ("io_uring", "denied"),
    ] {
        let v = got.get(k).cloned().unwrap_or_default();
        assert!(v.starts_with(want), "{k}: {v}, want {want}");
    }
    assert_eq!(
        got.get("token").map(String::as_str).unwrap_or(""),
        "",
        "the plugin saw rush's API key"
    );
    assert_eq!(got["home"], data.display().to_string());
    stop(child, conn);
    proxy.close();
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_preserves_approved_aliases_and_write_overlaps() {
    if let Err(e) = rush_plugin::supported() {
        assert!(!sandbox_is_required(), "plugin sandbox required: {e}");
        return;
    }
    let home = Home::new();
    let dir = rush_plugin::root().join("probe");
    std::fs::create_dir_all(&dir).unwrap();
    cargo_build("rush-plugin-probe", "probe", &dir.join("probe"));
    let writable = home.path().join("approved-write");
    std::fs::create_dir(&writable).unwrap();
    let readable = home.path().join("approved-read");
    std::fs::write(&readable, "approved content").unwrap();
    let mut manifest = json!({
        "name": "probe", "command": ["probe"],
        "read": [home.path(), writable], "write": [writable]
    });
    let write_manifest = |m: &Value| {
        std::fs::write(
            dir.join("plugin.json"),
            rush_state::json::to_vec(m).unwrap(),
        )
        .unwrap();
    };
    write_manifest(&manifest);
    // Both the plugin path and data environment retain the symlink spelling.
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("rush-home");
    std::os::unix::fs::symlink(home.path(), &alias).unwrap();
    rush_state::set_thread_dir(Some(alias));
    let alias_dir = rush_plugin::root().join("probe");
    let data = rush_plugin::data_dir("probe");
    let (child, conn) = start(&alias_dir, 0, Arc::new(|_, _, m, _| Err(no_method(m))));
    let ctx = Ctx::background().with_timeout(Duration::from_secs(20));
    let got: std::collections::BTreeMap<String, String> = conn
        .call(
            &ctx,
            "probe",
            &json!({
                "secret": readable, "outside": writable.join("planted"),
                "sock": home.path().join("absent.sock"), "data": data, "proxy": 0
            }),
        )
        .unwrap();
    for key in ["read secret", "write outside", "write data"] {
        assert_eq!(got[key], "allowed", "{key}: {got:?}");
    }
    assert_eq!(got["home"], data.to_string_lossy());
    stop(child, conn);

    // Broad grants cannot replace the private root or introduce host procfs.
    for rejected in [PathBuf::from("/"), {
        let p = home.path().join("host-proc");
        std::os::unix::fs::symlink("/proc", &p).unwrap();
        p
    }] {
        manifest["read"] = json!([rejected]);
        write_manifest(&manifest);
        let error = Launch {
            plugin: load(&alias_dir).unwrap(),
            proxy_port: 0,
        }
        .command()
        .unwrap_err();
        assert!(
            error.contains("host root") || error.contains("procfs"),
            "{error}"
        );
    }
}
