#!/bin/sh
# Install the reference MCP memory server into a plugin folder.
#
# The manifest names an absolute Node executable because rush gives plugins a
# clean PATH. Resolve it at install time so the same example works on macOS
# and Linux (and never falls back to an unsandboxed shell lookup).
set -eu

PACKAGE='@modelcontextprotocol/server-memory@2.1.0'
HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)

if [ "$#" -gt 0 ]; then
  destination=$1
else
  destination=${RUSH_PLUGIN_DIR:-}
fi
if [ -z "$destination" ]; then
  printf 'usage: %s <plugin-directory>\n' "$0" >&2
  printf 'or set RUSH_PLUGIN_DIR to the plugin directory\n' >&2
  exit 2
fi

node=$(command -v node 2>/dev/null || true)
case "$node" in
  /*) ;;
  *)
    printf 'node was not found as an absolute executable (command -v: %s)\n' "$node" >&2
    exit 1
    ;;
esac

mkdir -p "$destination"
npm install \
  --prefix "$destination" \
  --ignore-scripts \
  --no-audit \
  --no-fund \
  --save-exact \
  "$PACKAGE"

# Use Node to parse and write JSON rather than interpolating an executable
# path with sed. This keeps spaces, quotes, backslashes and shell metacharacters
# in an unusual installation path from changing the manifest's meaning.
RUSH_MEMORY_MANIFEST="$HERE/plugin.json" \
RUSH_MEMORY_NODE="$node" \
RUSH_MEMORY_DEST="$destination/plugin.json" \
"$node" - <<'NODE'
const fs = require('node:fs');

const manifestPath = process.env.RUSH_MEMORY_MANIFEST;
const nodePath = fs.realpathSync(process.env.RUSH_MEMORY_NODE);
const destination = process.env.RUSH_MEMORY_DEST;
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.command[0] = nodePath;
fs.writeFileSync(destination, `${JSON.stringify(manifest, null, 2)}\n`);
NODE
printf 'installed %s with %s\n' "$PACKAGE" "$node"
