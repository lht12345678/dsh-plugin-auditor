#!/bin/bash
# dsh-plugin-auditor build: link type deps from the running harness host,
# then compile src/ -> lib/ with the checkout's tsc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${DSH_HOST:-D:/DeepSeek harness/resources/host}"
HOST_NM="$HOST/node_modules"

# tsc + @types/node come from the selftest checkout (or DSH_CHECKOUT).
CHECKOUT="${DSH_CHECKOUT:-}"
if [ -z "$CHECKOUT" ] || [ ! -d "$CHECKOUT/packages" ]; then
  for c in "$HOME/dsh-harness" "$HOME/dsh" "$HOST/selftest-checkout"; do
    if [ -d "$c/packages" ]; then CHECKOUT="$c"; break; fi
  done
fi
if [ -z "$CHECKOUT" ] || [ ! -d "$CHECKOUT/node_modules/.bin" ]; then
  echo "build: cannot locate a checkout with node_modules/.bin (set DSH_CHECKOUT)" >&2
  exit 1
fi

TSC="$CHECKOUT/node_modules/.bin/tsc"
if [ ! -x "$TSC" ] && [ ! -f "$TSC.cmd" ]; then
  echo "build: tsc not found at $TSC" >&2
  exit 1
fi

link_pkg() {
  local target="$HOST_NM/$2"
  if [ ! -e "$target" ]; then
    echo "build: dependency target missing: $target" >&2
    exit 1
  fi
  node -e "
    const fs = require('fs');
    const path = require('path');
    const link = path.resolve(process.argv[1]);
    const target = path.resolve(process.argv[2]);
    fs.rmSync(link, { recursive: true, force: true });
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  " "node_modules/$1" "$target"
}

echo "=== Linking type dependencies (host: $HOST_NM) ==="
mkdir -p node_modules/@deepseek-ai
link_pkg cordis @deepseek-ai/cordis
link_pkg cosmokit @deepseek-ai/cosmokit
link_pkg schemastery @deepseek-ai/schemastery
link_pkg @deepseek-ai/dsh-tools @deepseek-ai/dsh-tools
link_pkg @deepseek-ai/dsh-llm @deepseek-ai/dsh-llm
link_pkg @deepseek-ai/dsh-system-prompt @deepseek-ai/dsh-system-prompt
link_pkg @deepseek-ai/dsh-session @deepseek-ai/dsh-session
link_pkg @deepseek-ai/cordis-plugin-loader @deepseek-ai/cordis-plugin-loader
if [ ! -e node_modules/@types/node ]; then
  node -e "
    const fs = require('fs');
    const path = require('path');
    fs.rmSync('node_modules/@types/node', { recursive: true, force: true });
    fs.mkdirSync('node_modules/@types', { recursive: true });
    fs.symlinkSync(path.resolve(process.argv[1]), path.resolve('node_modules/@types/node'), process.platform === 'win32' ? 'junction' : 'dir');
  " "$CHECKOUT/node_modules/@types/node"
fi

echo "=== Compiling src -> lib ==="
"$TSC" -p tsconfig.json
echo "=== Build complete ==="
