#!/usr/bin/env node
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  watch,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";

const checkoutArg = process.argv[2] || process.env.KANBAN_CODE_CHECKOUT;
const nodeArg = process.argv[3] || process.env.KANBAN_NODE || process.execPath;
if (!checkoutArg || process.argv.length > 4) {
  console.error(
    "usage: node test-cli.mjs /path/to/patched/kanban-code [absolute/path/to/node]"
  );
  process.exit(2);
}

const checkout = resolve(checkoutArg);
const nodePath = resolve(nodeArg);
const cliPath = join(checkout, "cli", "dist", "kanban.js");
const sourcePath = join(checkout, "cli", "src", "subagents.ts");
if (!existsSync(cliPath)) {
  throw new Error(`built CLI not found: ${cliPath}`);
}
if (!readFileSync(sourcePath, "utf8").includes("RUSH_LINUX_KANBAN_COMPAT_V1")) {
  throw new Error(`CLI source is not patched: ${sourcePath}`);
}

const CARD_ID = "card_linux_relink";
const SESSION_ID = "linux-session-001";
const tempRoot = mkdtempSync(join(process.env.TMPDIR || "/tmp", "rush-kanban-linux-"));
const home = join(tempRoot, "home");
const kanbanHome = join(tempRoot, "kanban-code");
const claudeHome = join(tempRoot, "claude");
const project = join(tempRoot, "project");
const inbox = join(kanbanHome, "commands", "inbox");
const responses = join(kanbanHome, "commands", "responses");
const sessionPath = join(claudeHome, "projects", "linux-project", `${SESSION_ID}.jsonl`);

const children = new Set();
function remember(child) {
  children.add(child);
  child.once("close", () => children.delete(child));
  return child;
}
function stop(child) {
  if (!child || child.exitCode !== null) return Promise.resolve();
  return new Promise((resolveStop) => {
    let force;
    const done = () => {
      clearTimeout(force);
      resolveStop();
    };
    child.once("close", done);
    child.kill("SIGTERM");
    force = setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
      done();
    }, 2_000);
  });
}

function runCli(args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = remember(
      spawn(nodePath, [cliPath, ...args], {
        cwd: project,
        env: testEnv,
        stdio: ["ignore", "pipe", "pipe"],
      })
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code, signal) => resolveRun({ code, signal, stdout, stderr }));
  });
}

function spawnServer(argv0) {
  const child = remember(
    spawn(
      nodePath,
      [
        "-e",
        `process.title = ${JSON.stringify(argv0)}; process.stdout.write("ready\\n"); process.stdin.resume(); setInterval(() => {}, 60_000);`,
      ],
      {
        argv0,
        env: testEnv,
        stdio: ["ignore", "pipe", "ignore"],
      }
    )
  );
  if (!child.pid) throw new Error(`could not start helper with argv0 ${argv0}`);
  if (child.exitCode !== null) throw new Error(`helper exited with argv0 ${argv0}`);
  // The child announces only after process.title has updated its Linux comm
  // name; this removes a race before the first pgrep-based negative check.
  const ready = new Promise((resolveReady, rejectReady) => {
    const timer = setTimeout(() => rejectReady(new Error(`helper ${argv0} was not ready`)), 2_000);
    child.once("close", () => {
      clearTimeout(timer);
      rejectReady(new Error(`helper ${argv0} exited before readiness`));
    });
    child.stdout.once("data", () => {
      clearTimeout(timer);
      resolveReady();
    });
  });
  return { child, ready };
}

function writeResponse(id, value) {
  const temp = join(responses, `${id}.json.tmp`);
  const target = join(responses, `${id}.json`);
  writeFileSync(temp, value);
  renameSync(temp, target);
}

/**
 * A mailbox engine that watches the same directories as the real app. It
 * acknowledges only after reading an atomically published request, so the
 * test exercises the CLI's real request/response protocol.
 */
function mailbox(mode) {
  let watcher;
  let timer;
  let settled = false;
  let resolveRequest;
  let rejectRequest;
  const request = new Promise((resolvePromise, rejectPromise) => {
    resolveRequest = resolvePromise;
    rejectRequest = rejectPromise;
  });
  const finish = (error, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    watcher?.close();
    if (error) rejectRequest(error);
    else resolveRequest(value);
  };
  const inspect = (name) => {
    if (settled || !name || !name.endsWith(".json")) return;
    const path = join(inbox, name);
    let raw;
    let value;
    try {
      raw = readFileSync(path, "utf8");
      value = JSON.parse(raw);
    } catch {
      // A rename publishes complete JSON; ignore unrelated partial files.
      return;
    }
    if (mode === "invalid") {
      writeResponse(value.id, "not-json\n");
    } else {
      writeResponse(
        value.id,
        `${JSON.stringify({ id: value.id, ok: true, cardId: value.cardId })}\n`
      );
    }
    finish(null, value);
  };
  watcher = watch(inbox, (_event, name) => inspect(name?.toString()));
  watcher.on("error", (error) => finish(error));
  timer = setTimeout(
    () => finish(new Error(`mailbox did not receive a request in ${mode} mode`)),
    15_000
  );
  for (const name of readdirSync(inbox)) inspect(name);
  return {
    request,
    close() {
      clearTimeout(timer);
      watcher?.close();
    },
  };
}

const pathEnv = `${dirname(nodePath)}${process.env.PATH ? `:${process.env.PATH}` : ""}`;
const testEnv = {
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  KANBAN_CODE_HOME: kanbanHome,
  CLAUDE_CONFIG_DIR: claudeHome,
  PATH: pathEnv,
};

mkdirSync(project, { recursive: true });
mkdirSync(inbox, { recursive: true });
mkdirSync(responses, { recursive: true });
mkdirSync(dirname(sessionPath), { recursive: true });
writeFileSync(
  sessionPath,
  [
    JSON.stringify({
      type: "user",
      cwd: project,
      message: { role: "user", content: "Review the Linux Kanban integration." },
    }),
    JSON.stringify({
      type: "assistant",
      cwd: project,
      message: {
        role: "assistant",
        content: [{ type: "text", text: "The integration is ready for review." }],
      },
    }),
  ].join("\n") + "\n"
);
writeFileSync(
  join(kanbanHome, "links.json"),
  JSON.stringify({
    links: [
      {
        id: CARD_ID,
        name: "Linux relink card",
        projectPath: project,
        column: "backlog",
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
        manualOverrides: {},
        manuallyArchived: false,
        source: "manual",
        isRemote: false,
        sessionLink: { sessionId: "old-session" },
      },
    ],
  })
);

try {
  // The Linux patch must reject an absent server before it writes a mailbox
  // request. This also prevents a stale Mac app name from authorizing Linux.
  const absent = await runCli(["relink", CARD_ID, SESSION_ID, "--json"]);
  if (absent.code === 0 || !absent.stderr.includes("Kanban Code is not running")) {
    throw new Error(`missing Linux server was accepted: ${JSON.stringify(absent)}`);
  }
  if (readdirSync(inbox).length !== 0) {
    throw new Error("missing Linux server left a mailbox request behind");
  }

  const macApp = spawnServer("KanbanCode");
  await macApp.ready;
  const macOnly = await runCli(["relink", CARD_ID, SESSION_ID, "--json"]);
  await stop(macApp.child);
  if (macOnly.code === 0 || !macOnly.stderr.includes("Kanban Code is not running")) {
    throw new Error(`Mac app process was accepted on Linux: ${JSON.stringify(macOnly)}`);
  }

  const linuxServer = spawnServer("kanban-code-server");
  await linuxServer.ready;
  const validMailbox = mailbox("valid");
  const [success, validRequest] = await Promise.all([
    runCli(["relink", CARD_ID, SESSION_ID, "--json"]),
    validMailbox.request,
  ]);
  validMailbox.close();
  if (success.code !== 0) {
    throw new Error(`relink failed with a real Linux server: ${success.stderr}`);
  }
  if (
    validRequest.operation !== "relinkSession" ||
    validRequest.parentCardId !== CARD_ID ||
    validRequest.cardId !== CARD_ID ||
    validRequest.sessionId !== SESSION_ID ||
    validRequest.sessionPath !== sessionPath ||
    typeof validRequest.id !== "string" ||
    typeof validRequest.createdAt !== "string"
  ) {
    throw new Error(`unexpected relink request payload: ${JSON.stringify(validRequest)}`);
  }
  const output = JSON.parse(success.stdout);
  if (
    output.cardId !== CARD_ID ||
    output.sessionId !== SESSION_ID ||
    output.sessionPath !== sessionPath
  ) {
    throw new Error(`unexpected relink output: ${success.stdout}`);
  }

  const invalidMailbox = mailbox("invalid");
  const [invalid] = await Promise.all([
    runCli(["relink", CARD_ID, SESSION_ID, "--json"]),
    invalidMailbox.request,
  ]);
  invalidMailbox.close();
  if (invalid.code === 0 || !invalid.stderr.includes("invalid subagent response")) {
    throw new Error(`invalid mailbox response was accepted: ${JSON.stringify(invalid)}`);
  }
  await stop(linuxServer.child);
  console.log("kanban Linux CLI guard and relink mailbox protocol passed");
} finally {
  await Promise.all([...children].map(stop));
  rmSync(tempRoot, { recursive: true, force: true });
}
