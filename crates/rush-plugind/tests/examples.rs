//! The broker running the example plugins in the repository, built from
//! their Rust source with cargo and sandboxed (and an MCP server built
//! from Go source, skipped without a Go toolchain), talked to as a session
//! host would: Claude Code's MCP messages in, the plugin's replies out.
//! Ported from internal/plugind/plugind_test.go and kanban_test.go.

// Every test runs in a throwaway home (rush-testenv).
rush_testenv::sandboxed!();

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use rush_plugin::Manifest;
use rush_plugind::{Broker, FileHosts, Info, Log, Scope};
use rush_sys::fswait::{File, Stop, grown};
use serde_json::value::RawValue;
use serde_json::{Value, json};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// A rush folder for this test's thread: short, under /tmp, as a unix
/// socket's path must be.
struct Home(tempfile::TempDir);

impl Home {
    fn new() -> Home {
        let d = tempfile::Builder::new()
            .prefix("rush-")
            .tempdir_in("/tmp")
            .unwrap();
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

/// Builds a Go program; false (and says why) without Go to build it with.
fn go_build(pkg: &Path, out: &Path) -> bool {
    match Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(out)
        .arg(".")
        .current_dir(pkg)
        .output()
    {
        Ok(o) if o.status.success() => true,
        Ok(o) => panic!("go build: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => {
            eprintln!("skipped: no Go toolchain ({e})");
            false
        }
    }
}

/// Builds the example plugin pkg, as cargo builds it, and copies its
/// program to out. It builds into a target folder of its own: the cargo
/// running the tests holds the workspace's.
fn cargo_build(pkg: &str, out: &Path) {
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
        pkg,
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
    rush_testenv::copy_executable(&target.join("debug").join(pkg), out).unwrap();
}

/// Copies a prepared MCP package without using a shell. npm may publish
/// symlinked files, so retain links rather than following them into a
/// runner-owned directory.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let kind = std::fs::symlink_metadata(&src).unwrap().file_type();
        if kind.is_dir() {
            copy_tree(&src, &dst);
        } else if kind.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(&src).unwrap(), &dst).unwrap();
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

fn sandbox_is_required() -> bool {
    (cfg!(target_os = "linux") && std::env::var_os("CI").is_some())
        || std::env::var_os("RUSH_TEST_REQUIRE_PLUGIN_SANDBOX").is_some()
        || std::env::var_os("PLUGIN_SANDBOX_REQUIRED").is_some()
}

fn prepared_memory_plugin() -> Option<PathBuf> {
    let source = std::env::var_os("MEMORY_PLUGIN_DIR")
        .or_else(|| std::env::var_os("RUSH_MEMORY_PLUGIN_DIR"))
        .map(PathBuf::from);
    if source.is_none() && sandbox_is_required() {
        panic!("MEMORY_PLUGIN_DIR is required for the Linux memory example test");
    }
    source
}

/// Runs a broker in home until nothing is approved; the broker, once it
/// listens, and what Run returned, when it does.
fn run_broker(home: &Home) -> (Broker, mpsc::Receiver<Result<(), String>>) {
    let logger = Arc::new(rush_events::Logger::new(Some(
        home.path().join("events.jsonl"),
    )));
    let scope = Scope::with_events(logger.clone());
    let dirs = rush_state::thread_dirs();
    let (ready_tx, ready) = mpsc::channel();
    let (done_tx, done) = mpsc::channel();
    std::thread::spawn(move || {
        rush_state::set_thread_dirs(dirs);
        let res = rush_plugind::run_with(
            Arc::new(FileHosts::logging_to(logger)),
            Log::discard(),
            scope,
            false,
            move |b| {
                let _ = ready_tx.send(b.clone());
            },
        );
        let _ = done_tx.send(res);
    });
    match ready.recv_timeout(Duration::from_secs(10)) {
        Ok(b) => (b, done),
        Err(_) => panic!("broker never listened: {:?}", done.try_recv()),
    }
}

/// Waits for the file at path to hold want, as it's written.
fn wait_file(path: &Path, want: &str) -> String {
    let stop = Arc::new(Stop::new().unwrap());
    let s = stop.clone();
    // A timer, not a look: it only ever ends the wait.
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(15));
        s.close();
    });
    loop {
        let b = std::fs::read_to_string(path).unwrap_or_default();
        if b.contains(want) {
            stop.close();
            return b;
        }
        let f = File {
            path: path.to_path_buf(),
            size: b.len() as u64,
        };
        if !grown(&stop, &[f]) {
            panic!("{} never held {want:?}; it has {b:?}", path.display());
        }
    }
}

fn mcp(b: &rush_plugin::Broker, plugin: &str, session: &str, msg: &str) -> Value {
    let m = RawValue::from_string(msg.to_string()).unwrap();
    serde_json::from_str(b.mcp(plugin, session, &m).get()).unwrap()
}

fn text(r: &Value) -> String {
    r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Builds plugins/examples/delegate, approves it, and talks to it as a
/// session host would.
#[test]
fn broker_runs_the_example_plugin() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let home = Home::new();
    let dir = rush_plugin::root().join("delegate");
    std::fs::create_dir_all(&dir).unwrap();
    let src = repo().join("plugins/examples/delegate");
    cargo_build("delegate", &dir.join("delegate"));
    std::fs::copy(src.join("plugin.json"), dir.join("plugin.json")).unwrap();
    let p = rush_plugin::load(&dir).unwrap();
    rush_plugin::approve(&p).unwrap();
    let (broker, done) = run_broker(&home);

    let b = rush_plugin::Broker::new();
    let init = mcp(
        &b,
        "delegate",
        "sess1",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
    );
    assert_eq!(
        init["result"]["serverInfo"]["name"], "rush-delegate",
        "{init}"
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let n = mcp(
        &b,
        "delegate",
        "sess1",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    assert!(!n["result"].is_null(), "notification reply = {n}");
    let list = mcp(
        &b,
        "delegate",
        "sess1",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    assert_eq!(
        list["result"]["tools"].as_array().map(Vec::len),
        Some(4),
        "{list}"
    );
    let call = |id: u32, tool: &str, args: Value| {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": args}});
        text(&mcp(&b, "delegate", "sess1", &msg.to_string()))
    };
    assert_eq!(call(3, "list_agents", json!({})), "No agents.");
    // Sessions it didn't start are out of its reach, and ids can't be paths.
    for id in ["someone-else", "../../plugin-data/delegate"] {
        let got = call(4, "message_agent", json!({"id": id, "text": "rm -rf ~"}));
        assert!(
            got.contains("no session") || got.contains("bad session id"),
            "message_agent({id}) = {got:?}"
        );
    }
    // Outside its workspaces, nothing starts.
    let got = call(5, "start_agent", json!({"cwd": "/tmp", "prompt": "hi"}));
    assert!(
        got.contains("outside the plugin's workspaces"),
        "start_agent in /tmp = {got:?}"
    );

    // It is started again when it dies.
    let st = rush_plugind::ask().unwrap();
    assert!(st.len() == 1 && st[0].state == "running", "status = {st:?}");
    let pid = st[0].pid;
    // SAFETY: kills the plugin the broker started for this test.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    let st = broker.wait_status("delegate", Duration::from_secs(10), |s| {
        s.state == "running" && s.pid != 0 && s.pid != pid && s.restarts == 1
    });
    assert!(st.is_some(), "not restarted: {:?}", broker.status());
    assert_eq!(
        call(6, "list_agents", json!({})),
        "No agents.",
        "after restart"
    );

    // Revoking the last plugin stops it, and the broker with it.
    rush_plugin::revoke("delegate").unwrap();
    rush_plugind::reload().unwrap();
    let res = done
        .recv_timeout(Duration::from_secs(10))
        .expect("broker still running with nothing approved");
    res.unwrap();
    assert!(
        !rush_plugin::broker_sock().exists(),
        "broker left its socket behind"
    );
}

/// Runs plugins/examples/kanban, sandboxed, against a kanban-code board
/// and CLI of its own: Claude reads the board and its card, the plugin has
/// kanban-code link the card to the agent it started for it, and a message
/// for the card reaches that agent.
#[test]
fn broker_runs_the_kanban_example() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let home = Home::new();
    let hp = home.path().to_string_lossy().into_owned();
    // kanban-code: a board with one card, and a CLI that notes what it's
    // asked.
    let kb = home.path().join("kb");
    std::fs::create_dir_all(&kb).unwrap();
    std::fs::write(
        kb.join("links.json"),
        format!(
            r#"{{"links": [{{"id": "card_bbb222", "column": "backlog",
            "projectPath": "{hp}", "sessionLink": {{"sessionId": "s-9"}}, "issueLink": {{"number": 12, "title": "Dark mode", "body": "Please."}},
            "manualOverrides": {{}}, "manuallyArchived": false, "source": "githubIssue", "isRemote": false,
            "createdAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-01T00:00:00Z"}}]}}"#
        ),
    )
    .unwrap();
    std::fs::write(kb.join("calls"), "").unwrap();
    let cli = home.path().join("bin/kanban");
    std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
    {
        rush_testenv::write_executable_with_mode(
            &cli,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}/calls\necho '{{}}'\n",
                kb.display()
            )
            .as_bytes(),
            0o700,
        )
        .unwrap();
    }

    // An agent the plugin started for the card, as its host publishes it.
    let info = Info {
        id: "k1".into(),
        session_id: "s-9".into(),
        cwd: hp.clone(),
        state: "idle".into(),
        host_pid: std::process::id() as i64,
        started_by: "kanban".into(),
        meta: [("card".to_string(), "card_bbb222".to_string())].into(),
        ..Default::default()
    };
    let sd = rush_plugind::host::root().join("k1");
    std::fs::create_dir_all(&sd).unwrap();
    std::fs::write(sd.join("info.json"), serde_json::to_vec(&info).unwrap()).unwrap();

    let dir = rush_plugin::root().join("kanban");
    std::fs::create_dir_all(&dir).unwrap();
    cargo_build("kanban", &dir.join("kanban"));
    let m = Manifest {
        name: "kanban".into(),
        command: vec!["kanban".into()],
        tools: true,
        sidebar: true,
        sessions: vec!["list".into(), "start".into(), "queue".into()],
        workspaces: vec![hp.clone()],
        read: vec![kb.to_string_lossy().into_owned()],
        env: [(
            "KANBAN_CODE_HOME".to_string(),
            kb.to_string_lossy().into_owned(),
        )]
        .into(),
        exec: [(
            "kanban".to_string(),
            vec![cli.to_string_lossy().into_owned()],
        )]
        .into(),
        ..Default::default()
    };
    std::fs::write(
        dir.join("plugin.json"),
        rush_state::json::to_vec(&m).unwrap(),
    )
    .unwrap();
    let p = rush_plugin::load(&dir).unwrap();
    rush_plugin::approve(&p).unwrap();
    let (_broker, done) = run_broker(&home);

    let b = rush_plugin::Broker::new();
    let call = |tool: &str, args: &str| {
        let msg = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
        );
        let r = mcp(&b, "kanban", "k1", &msg);
        let t = text(&r);
        assert!(!t.is_empty(), "{tool}: {r}");
        t
    };
    let got = call("board", "{}");
    assert!(
        got.contains("## Backlog\n- card_bbb222  Dark mode"),
        "board = {got:?}"
    );
    // The card comes from the meta rush hands along with the call.
    let got = call("my_card", "{}");
    assert!(got.contains("Issue #12: Dark mode"), "my_card = {got:?}");
    let got = call("start_card", r#"{"card": "card_bbb222"}"#);
    assert!(
        got.contains("already being worked on"),
        "start_card on a card with an agent = {got:?}"
    );
    // Reaches the agent: it isn't really running, so rush says so.
    let got = call("card_message", r#"{"card": "dark mode", "text": "hi"}"#);
    assert!(got.contains("k1 is not running"), "card_message = {got:?}");

    // Watching, it saw the agent's conversation, and linked the card to it.
    wait_file(&kb.join("calls"), "relink card_bbb222 s-9 --json");
    // It arranged rush's list as the board.
    wait_file(
        &rush_plugin::sidebar::sidebar_path("kanban"),
        r#""s-9":{"name":"Dark mode","section":"Backlog""#,
    );

    rush_plugin::revoke("kanban").unwrap();
    let _ = rush_plugind::reload();
    done.recv_timeout(Duration::from_secs(10))
        .expect("broker still running with nothing approved")
        .unwrap();
    assert!(
        !rush_plugin::sidebar::sidebar_path("kanban").exists(),
        "revoked, its sidebar stayed"
    );
}

/// Runs the real reference MCP memory server from its prepared npm package,
/// then restarts it and reads the graph back from the plugin data folder.
/// There is no model account involved: all requests are direct MCP calls.
#[test]
fn broker_runs_memory_and_persists_the_graph_across_restart() {
    let Some(source) = prepared_memory_plugin() else {
        return;
    };
    if rush_plugin::supported().is_err() {
        if sandbox_is_required() {
            panic!("plugin sandbox required for the memory example");
        }
        return;
    }
    assert!(
        source.join("plugin.json").is_file(),
        "missing memory manifest"
    );
    assert!(
        source
            .join("node_modules/@modelcontextprotocol/server-memory/dist/index.js")
            .is_file(),
        "prepared memory package is missing the server entrypoint"
    );

    let home = Home::new();
    let dir = rush_plugin::root().join("memory");
    copy_tree(&source, &dir);
    let p = rush_plugin::load(&dir).unwrap_or_else(|e| panic!("memory manifest: {e}"));
    rush_plugin::approve(&p).unwrap();
    let (broker, done) = run_broker(&home);
    broker
        .wait_status("memory", Duration::from_secs(20), |s| s.state == "running")
        .unwrap_or_else(|| panic!("memory did not start: {:?}", broker.status()));

    let b = rush_plugin::Broker::new();
    let init = mcp(
        &b,
        "memory",
        "memory-test",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rush-memory-test","version":"1"}}}"#,
    );
    assert!(init["result"].is_object(), "memory initialize = {init}");
    let _ = mcp(
        &b,
        "memory",
        "memory-test",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let tools = mcp(
        &b,
        "memory",
        "memory-test",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("memory tools/list = {tools}"))
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for name in ["create_entities", "search_nodes", "read_graph"] {
        assert!(
            names.contains(&name),
            "memory tools/list lacks {name}: {tools}"
        );
    }

    let call = |id: u32, name: &str, args: Value| {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        });
        let response = mcp(&b, "memory", "memory-test", &msg.to_string());
        assert!(response["error"].is_null(), "memory {name} = {response}");
        assert!(response["result"].is_object(), "memory {name} = {response}");
        text(&response)
    };
    let created = call(
        3,
        "create_entities",
        json!({"entities": [
            {"name": "RushLinuxMemory", "entityType": "project", "observations": ["survives a broker restart"]},
            {"name": "LinuxCI", "entityType": "environment", "observations": ["runs the six plugin examples"]}
        ]}),
    );
    assert!(
        created.contains("RushLinuxMemory"),
        "create_entities = {created}"
    );
    let related = call(
        4,
        "create_relations",
        json!({"relations": [{"from": "RushLinuxMemory", "to": "LinuxCI", "relationType": "validated_by"}]}),
    );
    assert!(
        related.contains("validated_by"),
        "create_relations = {related}"
    );

    // The server's configured data path is the plugin's private folder, so a
    // successful write is also evidence that no real home was used.
    let memory_file = rush_plugin::data_dir("memory").join("memory.jsonl");
    wait_file(&memory_file, "RushLinuxMemory");

    let pid = broker
        .status()
        .into_iter()
        .find(|s| s.name == "memory" && s.state == "running")
        .map(|s| s.pid)
        .unwrap_or_else(|| panic!("memory had no running pid: {:?}", broker.status()));
    // SAFETY: this is the memory plugin process started by this test's broker.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    broker
        .wait_status("memory", Duration::from_secs(20), |s| {
            s.state == "running" && s.pid != pid && s.restarts >= 1
        })
        .unwrap_or_else(|| panic!("memory was not restarted: {:?}", broker.status()));

    let searched = call(5, "search_nodes", json!({"query": "RushLinuxMemory"}));
    assert!(
        searched.contains("survives a broker restart"),
        "search_nodes = {searched}"
    );
    let opened = call(6, "open_nodes", json!({"names": ["RushLinuxMemory"]}));
    assert!(
        opened.contains("survives a broker restart"),
        "open_nodes = {opened}"
    );
    let graph = call(7, "read_graph", json!({}));
    assert!(
        graph.contains("RushLinuxMemory") && graph.contains("validated_by"),
        "read_graph = {graph}"
    );

    rush_plugin::revoke("memory").unwrap();
    rush_plugind::reload().unwrap();
    done.recv_timeout(Duration::from_secs(10))
        .expect("broker still running with no approved memory plugin")
        .unwrap();
}

/// The Linux broker's memory check must include the MCP server below
/// bubblewrap, not only bubblewrap's small monitor process.  This fixture is
/// deliberately dependency-free: the prepared memory plugin supplies the
/// absolute Node interpreter that the CI installer resolved.
#[cfg(target_os = "linux")]
#[test]
fn broker_enforces_memory_mb_for_descendant_node() {
    let Some(source) = prepared_memory_plugin() else {
        return;
    };
    if rush_plugin::supported().is_err() {
        if sandbox_is_required() {
            panic!("plugin sandbox required for the descendant memory test");
        }
        return;
    }

    let prepared =
        rush_plugin::load(&source).unwrap_or_else(|e| panic!("prepared memory manifest: {e}"));
    let node = prepared
        .command
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("prepared memory manifest has no Node command"));

    let home = Home::new();
    let dir = rush_plugin::root().join("memory-limit");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("fixture.mjs"),
        r#"// Keep resident pages alive so the broker measures the descendant.
globalThis.rushMemoryFixture = Buffer.alloc(64 * 1024 * 1024, 0x5a);

let pending = "";
function reply(id, result) {
  process.stdout.write(JSON.stringify({jsonrpc: "2.0", id, result}) + "\n");
}
function error(id, message) {
  process.stdout.write(JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: {code: -32601, message}
  }) + "\n");
}
function handle(line) {
  let request;
  try {
    request = JSON.parse(line);
  } catch (_) {
    return;
  }
  if (request.id === undefined) {
    return;
  }
  switch (request.method) {
    case "initialize":
      reply(request.id, {
        protocolVersion: request.params?.protocolVersion ?? "2025-06-18",
        capabilities: {tools: {}},
        serverInfo: {name: "memory-limit", version: "1"}
      });
      break;
    case "tools/list":
      reply(request.id, {
        tools: [{
          name: "memory_fixture",
          description: "A dependency-free MCP memory-limit fixture.",
          inputSchema: {type: "object", properties: {}}
        }]
      });
      break;
    case "tools/call":
      reply(request.id, {content: [{type: "text", text: "ok"}]});
      break;
    default:
      error(request.id, "no " + request.method);
  }
}
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  pending += chunk;
  let end;
  while ((end = pending.indexOf("\n")) >= 0) {
    const line = pending.slice(0, end).trim();
    pending = pending.slice(end + 1);
    if (line) {
      handle(line);
    }
  }
});
"#,
    )
    .unwrap();
    let manifest = Manifest {
        name: "memory-limit".into(),
        protocol: rush_plugin::PROTO_MCP.into(),
        command: vec![node, "fixture.mjs".into()],
        memory_mb: 16,
        ..Default::default()
    };
    std::fs::write(
        dir.join("plugin.json"),
        rush_state::json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let p = rush_plugin::load(&dir).unwrap();
    rush_plugin::approve(&p).unwrap();
    let (broker, done) = run_broker(&home);
    broker
        .wait_status("memory-limit", Duration::from_secs(10), |s| {
            s.state == "running"
        })
        .unwrap_or_else(|| panic!("memory fixture did not start: {:?}", broker.status()));

    // Complete the MCP handshake and tools/list before waiting for the
    // broker's periodic memory check to kill the oversized descendant.
    let b = rush_plugin::Broker::new();
    let init = mcp(
        &b,
        "memory-limit",
        "memory-limit-test",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rush-memory-limit-test","version":"1"}}}"#,
    );
    assert!(
        init["result"].is_object(),
        "memory-limit initialize = {init}"
    );
    let _ = mcp(
        &b,
        "memory-limit",
        "memory-limit-test",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let tools = mcp(
        &b,
        "memory-limit",
        "memory-limit-test",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    assert_eq!(
        tools["result"]["tools"][0]["name"], "memory_fixture",
        "memory-limit tools/list = {tools}"
    );

    let exceeded = broker.wait_status("memory-limit", Duration::from_secs(20), |s| {
        s.error.contains("over its 16 MB limit")
    });

    // Revoke even when the monitor's assertion fails, so the broker thread
    // cannot leak into the next integration test.
    rush_plugin::revoke("memory-limit").unwrap();
    rush_plugind::reload().unwrap();
    done.recv_timeout(Duration::from_secs(10))
        .expect("broker still running with no approved memory-limit plugin")
        .unwrap();
    assert!(
        exceeded.is_some(),
        "descendant Node allocation did not exceed its limit: {:?}",
        broker.status()
    );
}

/// An MCP server runs as a plugin as it is: initialized as any MCP client
/// would, its own guidance passed on, its tools called through.
#[test]
fn broker_runs_an_mcp_plugin() {
    if rush_plugin::supported().is_err() {
        return;
    }
    let home = Home::new();
    let dir = rush_plugin::root().join("echo");
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/mcpecho");
    if !go_build(&src, &dir.join("echo")) {
        return;
    }
    let m = Manifest {
        name: "echo".into(),
        protocol: rush_plugin::PROTO_MCP.into(),
        command: vec!["echo".into()],
        ..Default::default()
    };
    std::fs::write(
        dir.join("plugin.json"),
        rush_state::json::to_vec(&m).unwrap(),
    )
    .unwrap();
    rush_plugin::approve(&rush_plugin::load(&dir).unwrap()).unwrap();
    let (broker, done) = run_broker(&home);
    broker
        .wait_status("echo", Duration::from_secs(10), |s| s.state == "running")
        .unwrap_or_else(|| panic!("not running: {:?}", broker.status()));

    let b = rush_plugin::Broker::new();
    let init = mcp(
        &b,
        "echo",
        "s1",
        r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
    );
    assert_eq!(
        init,
        json!({"id": "a", "jsonrpc": "2.0", "result": {"capabilities": {"tools": {}},
            "instructions": "Echo things.", "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "rush-echo", "version": ""}}})
    );
    let list = mcp(
        &b,
        "echo",
        "s1",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    assert_eq!(list["result"]["tools"][0]["name"], "echo", "{list}");
    let got = mcp(
        &b,
        "echo",
        "s1",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
    );
    assert_eq!(text(&got), "echo: hi", "{got}");
    let got = mcp(
        &b,
        "echo",
        "s1",
        r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#,
    );
    assert_eq!(got["error"]["code"], -32601, "{got}");

    rush_plugin::revoke("echo").unwrap();
    rush_plugind::reload().unwrap();
    done.recv_timeout(Duration::from_secs(10))
        .expect("broker still running with nothing approved")
        .unwrap();
}
