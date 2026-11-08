# Kanban Code on Linux

The Kanban Code CLI currently decides that the Kanban Code app is running with
`pgrep -x KanbanCode`. That is the macOS app name; Linux's headless
`kanban-code-server` has a different process name, and Linux `comm` values are
limited to 15 bytes. The Rush Linux example therefore carries an explicit,
fail-closed source patch for the CLI's process guard.

The patch is intentionally applied to an explicit official checkout. It does
not alter an installed user CLI, and it refuses to run when the reviewed
upstream helper is missing or has changed. Re-running it is safe: the marker is
checked and the already-patched source is left untouched.

The patch was reviewed against upstream commit
`2a0a0fcca154a3dbba5ef972fc3ac50da1acadf4` (2026-11-06):

Use `plugins/kanban/linux/patch-cli.mjs` from the extracted Linux download,
or `plugins/examples/kanban/linux/patch-cli.mjs` from a Rush source checkout.
Pass the path to your official Kanban Code checkout:

```sh
# From the extracted Rush Linux download:
node plugins/kanban/linux/patch-cli.mjs /path/to/kanban-code
# From a Rush source checkout instead:
# node plugins/examples/kanban/linux/patch-cli.mjs /path/to/kanban-code
```

Build the official CLI with its checked-in lockfile. Node 20 or newer and
pnpm 10.30.3 are required by the official `cli/package.json`:

```sh
npx --yes pnpm@10.30.3 --dir /path/to/kanban-code/cli install --frozen-lockfile --ignore-scripts
npx --yes pnpm@10.30.3 --dir /path/to/kanban-code/cli run build
```

The shipped Rush manifest expects the installed wrapper at
`~/.local/bin/kanban`. Install the official wrapper as your Linux user:

```sh
make -C /path/to/kanban-code PNPM="npx --yes pnpm@10.30.3" install-cli
export PATH="$HOME/.local/bin:$PATH"
```

That explicit command installs or updates `~/.local/bin/kanban` to point at
the checkout's built `cli/dist/kanban.js`. Keep the checkout in place while
using the wrapper. Then review and approve the Rush plugin with
`rush plugin approve kanban`.

The official headless `kanban-code-server` must still be running as the same
user, with the same board and locally available Claude transcripts. Install
`procps` for `pgrep` (`sudo apt-get install procps` on Ubuntu). The upstream
[server deployment scripts](https://github.com/langwatch/kanban-code/tree/2a0a0fcca154a3dbba5ef972fc3ac50da1acadf4/Scripts/kanban-code-server)
describe that separate service. The patch recognizes its process and retains
the server's validated `relinkSession` mailbox acknowledgment.

## CI protocol check

After the build, CI runs the actual compiled CLI (not a fake replacement):

```sh
node plugins/examples/kanban/linux/test-cli.mjs /path/to/kanban-code
```

The harness sets temporary `HOME`, `KANBAN_CODE_HOME`, and
`CLAUDE_CONFIG_DIR` values, writes a valid `links.json` and discoverable Claude
transcript, and watches the official command mailbox with `fs.watch`. It
starts only its own same-user helper processes: a Linux-style
`kanban-code-server` process for the successful case and a `KanbanCode`-named
process to prove the stale macOS guard is rejected. It verifies the exact
`relinkSession` request (`cardId`, session id, and transcript path), the CLI's
JSON result, and rejection of an invalid mailbox response. Every helper and
temporary directory is cleaned up by the script.

CI builds the pinned official CLI and uses a controlled mailbox fixture.
It does not deploy the Swift server or validate a production Kanban board.
