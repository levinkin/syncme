#!/bin/sh
# runs `syncme-mcp setup` against a throwaway home with fake agent clis and checks every config it writes
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
home="$work/home"
bin="$work/bin"
support="$home/Library/Application Support"
mkdir -p "$bin" "$support/Claude" "$support/Code/User/globalStorage/saoudrizwan.claude-dev/settings" \
  "$support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings" "$home/.cursor" "$home/.codeium/windsurf" \
  "$home/.gemini" "$home/.qwen" "$home/.kiro/settings" "$home/.copilot" "$home/.config/opencode" "$home/.config/amp"
echo '{"theme": "dark", "mcpServers": {"other": {"command": "x"}}}' > "$home/.gemini/settings.json"
for cli in claude codex hermes code; do
  printf '#!/bin/sh\necho "$0 $*" >> "%s/calls"\n/bin/cat >> "%s/stdin"\n' "$work" "$work" > "$bin/$cli"
  chmod +x "$bin/$cli"
done
ln -s "$(command -v node)" "$bin/node"
HOME="$home" PATH="$bin" node "$root/syncme.js" setup > "$work/out.json"
cat "$work/out.json"
HOME="$home" WORK="$work" node --input-type=module -e '
import {readFileSync} from "node:fs";
import assert from "node:assert/strict";
const home = process.env.HOME, work = process.env.WORK, support = home + "/Library/Application Support";
const read = file => JSON.parse(readFileSync(file, "utf8"));
const out = read(work + "/out.json");
const server = {command: "npx", args: ["-y", "syncme-mcp@latest"]};
assert.deepEqual(out.configured, ["claude desktop", "cursor", "windsurf", "gemini", "qwen", "kiro", "copilot cli", "opencode", "amp", "cline", "roo code", "claude cli", "codex cli", "hermes cli", "code cli"]);
assert.deepEqual(out.failed, []);
for (const file of [support + "/Claude/claude_desktop_config.json", home + "/.cursor/mcp.json", home + "/.codeium/windsurf/mcp_config.json", home + "/.qwen/settings.json", home + "/.kiro/settings/mcp.json", support + "/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", support + "/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"])
  assert.deepEqual(read(file).mcpServers.syncme, server, file);
assert.deepEqual(read(home + "/.gemini/settings.json"), {theme: "dark", mcpServers: {other: {command: "x"}, syncme: server}});
assert.deepEqual(read(home + "/.copilot/mcp-config.json").mcpServers.syncme, {type: "local", ...server, tools: ["*"]});
assert.deepEqual(read(home + "/.config/opencode/opencode.json").mcp.syncme, {type: "local", command: ["npx", "-y", "syncme-mcp@latest"], enabled: true});
assert.deepEqual(read(home + "/.config/amp/settings.json")["amp.mcpServers"].syncme, server);
const calls = readFileSync(work + "/calls", "utf8");
assert.match(calls, /claude mcp add --scope user syncme -- npx -y syncme-mcp@latest/);
assert.match(calls, /codex mcp add syncme -- npx -y syncme-mcp@latest/);
assert.match(calls, /hermes mcp add syncme --command npx --args -y syncme-mcp@latest/);
assert.match(calls, /code --add-mcp \{"name":"syncme","command":"npx","args":\["-y","syncme-mcp@latest"\]\}/);
assert.equal(readFileSync(work + "/stdin", "utf8"), "y\n");
console.log("setup e2e passed");
'
