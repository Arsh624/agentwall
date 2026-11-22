#!/bin/sh
# SessionStart hook: tell Claude when an MCP server of this project does not go
# through agentwall, or when agentwall is not installed. Silent when all is well.
aw=""
for c in agentwall "$HOME/.local/bin/agentwall" "${LOCALAPPDATA:-/nonexistent}/agentwall/agentwall.exe"; do
	if command -v "$c" >/dev/null 2>&1; then
		aw=$c
		break
	fi
done
if [ -z "$aw" ]; then
	echo "agentwall (the MCP firewall plugin) is not installed yet. Offer the user to run /agentwall:setup, which installs it and puts this project's MCP servers behind it."
	exit 0
fi
out=$("$aw" init --check 2>/dev/null)
if [ -n "$out" ]; then
	echo "$out"
	echo "Offer the user to run /agentwall:setup (or \`$aw init --apply\`) to protect these servers, then to restart Claude Code."
fi
exit 0
