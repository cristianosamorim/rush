#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const MARKER = "// RUSH_LINUX_KANBAN_COMPAT_V1";
const checkout = process.argv[2];
if (!checkout || process.argv.length > 3) {
  console.error("usage: node patch-cli.mjs /path/to/kanban-code");
  process.exit(2);
}

const sourcePath = resolve(checkout, "cli", "src", "subagents.ts");
const rawSource = readFileSync(sourcePath, "utf8");
// Git checkouts on Windows may carry CRLF. Match the reviewed source in a
// normalized form, then preserve that checkout's line ending when writing.
const lineEnding = rawSource.includes("\r\n") ? "\r\n" : "\n";
const source = rawSource.replaceAll("\r\n", "\n");

// Keep this exact: a changed upstream helper must be reviewed before this
// compatibility patch is applied to it.
const original = `export function kanbanCodeIsRunning(): boolean {
  try {
    execFileSync("pgrep", ["-x", "KanbanCode"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}`;

const patched = `${MARKER}
export function kanbanCodeIsRunning(): boolean {
  try {
    if (process.platform === "linux") {
      if (typeof process.getuid !== "function") return false;
      // Linux comm names are limited to 15 bytes; match the full argv and
      // constrain it to this user so another user's server cannot authorize a
      // mailbox request from this CLI.
      execFileSync(
        "pgrep",
        ["-u", String(process.getuid()), "-f", "(^|/)kanban-code-server([[:space:]]|$)"],
        { stdio: "ignore" }
      );
    } else {
      execFileSync("pgrep", ["-x", "KanbanCode"], { stdio: "ignore" });
    }
    return true;
  } catch {
    return false;
  }
}`;

const markerCount = source.split(MARKER).length - 1;
if (markerCount > 0) {
  if (markerCount !== 1 || !source.includes(patched)) {
    throw new Error(`refusing to trust an unexpected existing patch in ${sourcePath}`);
  }
  console.log(`already patched ${sourcePath}`);
  process.exit(0);
}

const matches = source.split(original).length - 1;
if (matches !== 1) {
  throw new Error(
    `refusing to patch ${sourcePath}: expected exactly one known kanbanCodeIsRunning helper, found ${matches}`
  );
}

const updated = source.replace(original, patched);
writeFileSync(sourcePath, lineEnding === "\n" ? updated : updated.replaceAll("\n", lineEnding));
console.log(`patched ${sourcePath} for Linux kanban-code-server detection`);
