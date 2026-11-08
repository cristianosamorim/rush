# Linux

This fork adds an experimental Linux port of the Rust Rush. The first
build target is x86_64 GNU/Linux on Ubuntu 24.04, including Ubuntu 24.04
in WSL2. Native Windows is not a build target.

## Install from source

Install Git, a C compiler/linker and Rust 1.98.1 or newer, with Cargo.
On Ubuntu, `build-essential` provides the C toolchain. Follow the
[official Rust installation instructions](https://rust-lang.org/tools/install/)
for Rust.

```sh
git clone --branch codex/linux-port https://github.com/cristianosamorim/rush.git
cd rush
cargo install --locked --path crates/rush
rush
```

Cargo installs the executable in `~/.cargo/bin`; that directory must be
on `PATH`. Install and sign in to the Linux versions of the coding
agents you want to use in the same Linux environment. Rush does not
install their programs or include model subscriptions or API credits.

To update a source installation:

```sh
git pull --ff-only
cargo install --locked --path crates/rush --force
```

Source builds do not replace themselves with an upstream macOS release.
Linux release checks use this fork. The existing macOS Homebrew install
continues to use the upstream tap.

## Build downloads

The [Linux workflow](https://github.com/cristianosamorim/rush/actions/workflows/linux.yml)
builds the executable after formatting, Clippy and workspace tests pass.
Each successful run publishes a `rush-linux-x86_64` artifact. These
artifacts are temporary CI builds, not a stable Linux release.

Download the artifact from a successful run while signed in to GitHub,
then unzip it. In the extracted folder, verify and install the binary:

```sh
sha256sum -c rush-linux-x86_64.tar.gz.sha256
tar -xzf rush-linux-x86_64.tar.gz
install -Dm755 rush "$HOME/.local/bin/rush"
```

Ensure `~/.local/bin` is on `PATH`, then run `rush`. The binary targets
Ubuntu 24.04; older distributions with an older glibc may need a source
build on that distribution instead.

## Platform differences

- The terminal UI, session hosts, provider adapters and bundled plugins
  use Linux backends. Processes and resource readings come from `/proc`
  and `/sys`; Linux file and process notification mechanisms replace
  Darwin's kqueue and FSEvents paths.
- Account credentials use Rush's existing private file vault on Linux,
  with private directories and files. macOS continues to use Keychain.
- Cache files follow `XDG_CACHE_HOME`, falling back to `~/.cache`.
- Desktop links use `xdg-open`. Image pasting needs `wl-clipboard` on
  Wayland or `xclip` on X11. Text copying uses the terminal's OSC 52
  support. Notifications need `notify-send` and a desktop notification
  service; a headless terminal still shows which agents need you.
- Apple's menu bar app, on-device speech recognition, Apple Intelligence
  and transparent APFS compression remain macOS features. Their native
  libraries are not linked into the Linux executable.
- Away detection uses inactivity inside Rush on Linux. Global keyboard
  and mouse idle time and the desktop's lock status are unavailable.
- Installed third-party plugins use the Linux sandbox described below.
  If its prerequisites are unavailable, Rush refuses to run them.
  Bundled plugins remain available according to their own requirements.
- `rush serve` can be run manually or managed by a Linux user service.
  The automatic Remote mode switch installs a macOS LaunchAgent and is
  unavailable on Linux.

The CI exercises the program with isolated test homes and fake provider
processes. A successful build does not establish compatibility with every
Linux desktop, distribution, installed provider version or real account.

## External plugins

Linux GNU builds on x86_64 and aarch64 use Bubblewrap and the kernel's
seccomp user-notification support. Ubuntu 24.04 x86_64 is the CI target;
other kernels, architectures and WSL2 installations must pass Rush's
runtime preflight. The kernel must support unprivileged user, mount,
PID and network namespaces, seccomp notifications and `close_range`
(Linux 5.11 or newer). Running without a sandbox is never a fallback.

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install bubblewrap apparmor-profiles
```

Ubuntu's AppArmor policy can restrict the namespace capabilities needed
by Bubblewrap. If AppArmor is enabled, load the distribution's profile
for `/usr/bin/bwrap`:

```sh
sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
```

This grants namespace setup to that executable and confines its children;
it does not disable the system's user-namespace protection. If the profile
is missing, install the distribution's current `apparmor-profiles`
package. On a kernel without AppArmor, including some WSL2 kernels,
loading an AppArmor profile is unnecessary. Container administrators may
also need to allow these namespace/seccomp features. Rush reports a
preflight error when they are denied.

The six repository examples use the same approval flow:

```sh
rush plugin check neighbours
rush plugin approve neighbours
rush plugin list
```

Install each example first, following [the examples guide](../plugins/README.md#examples).
The Rust examples are `neighbours`, `kanban`, `delegate`, `autodrafts`
and `reconnect`. The `memory` installer selects an absolute Node path
and installs the reference MCP memory server; Node and npm must be
installed in Linux. `kanban` also needs kanban-code's files and CLI at
the paths named in its manifest. A host tool requested through the
approved `exec` capability runs through Rush's broker.

The Linux sandbox exposes the plugin folder and libraries read-only,
its data and approved write paths read-write, and a private `/proc`.
Only its approved initial program can execute. Threads and connected
Unix stream pairs used by language runtimes are allowed; subprocesses,
pathname Unix sockets and direct network access are denied. Network
plugins reach only their private loopback relay, which forwards to
Rush's existing approved-host CONNECT proxy. The broker accounts for
the complete sandbox process tree when checking `memoryMB`.

Use an explicit interpreter path in `command`, such as
`["/usr/bin/python3", "main.py"]`. Shell wrappers and
`#!/usr/bin/env node` that execute a second program are blocked. Install
interpreters' dependencies before approving the plugin; any subsequent
change to its folder requires approval again.
