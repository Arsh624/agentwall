---
name: setup
description: Install agentwall (the local MCP firewall) if it is missing and put every MCP server of this project and of the user's Claude Code config behind it. Use when the user runs /agentwall:setup, asks to set up or install agentwall, or when the session-start check says an MCP server is not protected.
---

# Set up agentwall

agentwall runs each MCP server behind a firewall: it blocks the lethal trifecta (untrusted input + private data + a tool that sends data out), hides poisoned or changed tools, and keeps secrets out of what the agent sees. Do these steps in order, running the commands yourself, and tell the user what each one did.

## 1. Find agentwall

Run `agentwall --version`. If that fails, try `~/.local/bin/agentwall --version` (macOS, Linux) or `"$LOCALAPPDATA/agentwall/agentwall.exe" --version` (Windows). Use the first one that works as AGENTWALL in the steps below. If none works, install it (step 2); otherwise go to step 3.

## 2. Install it (only if it is missing)

Tell the user you are about to download the latest release from https://github.com/Arsh624/agentwall/releases and check its SHA-256 checksum, then:

- macOS or Linux:

  ```sh
  curl -fsSL https://raw.githubusercontent.com/Arsh624/agentwall/main/install.sh | sh
  ```

  It installs `~/.local/bin/agentwall` and refuses a binary whose checksum does not match.

- Windows (PowerShell):

  ```powershell
  $ErrorActionPreference = 'Stop'
  $tag = (Invoke-RestMethod https://api.github.com/repos/Arsh624/agentwall/releases/latest).tag_name
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
  $zip = "agentwall_$($tag.TrimStart('v'))_windows_$arch.zip"
  $base = "https://github.com/Arsh624/agentwall/releases/download/$tag"
  Invoke-WebRequest "$base/$zip" -OutFile "$env:TEMP\$zip"
  Invoke-WebRequest "$base/checksums.txt" -OutFile "$env:TEMP\agentwall-checksums.txt"
  $want = ((Get-Content "$env:TEMP\agentwall-checksums.txt") | Where-Object { $_ -like "*  $zip" }).Split(' ')[0]
  $got = (Get-FileHash "$env:TEMP\$zip" -Algorithm SHA256).Hash.ToLower()
  if (-not $want -or $got -ne $want) { throw "checksum mismatch, not installing" }
  Expand-Archive "$env:TEMP\$zip" -DestinationPath "$env:LOCALAPPDATA\agentwall" -Force
  & "$env:LOCALAPPDATA\agentwall\agentwall.exe" --version
  ```

If the download or the checksum fails, stop and show the user the error. Never install a binary whose checksum did not match.

## 3. Write the policy and the audit key

Run `AGENTWALL init` in the project directory. It writes the default policy to `~/.agentwall/policy.yaml` (never over an existing one) and creates the key that signs the audit log. If it says the vault is unavailable, tell the user the audit log will be unsigned until a keychain or `AGENTWALL_PASSPHRASE` is available.

## 4. Put the MCP servers behind agentwall

Run `AGENTWALL init --apply` in the project directory. It rewrites `.mcp.json`, Cursor's `mcp.json` and the user's and this project's servers in `~/.claude.json`, so every stdio server starts through agentwall. It backs up each file it changes and prints the backup path. HTTP servers are listed with the `agentwall proxy` command to run instead.

Then run `AGENTWALL init --check`. No output means every stdio server is protected.

## 5. Finish

Tell the user:

- which servers are now protected, and where the backups are (copy a backup back over its file to undo);
- to restart Claude Code (exit and start it again) so the servers start through agentwall;
- that a blocked call shows up as an error starting with "agentwall blocked this call", that `AGENTWALL log` shows every decision, and that `AGENTWALL verify` checks the audit log;
- if `init` mentioned secrets in a server's `env`: they can move each one into the vault with `AGENTWALL secret set <name>` and a `vault:<name>` entry in the policy, so the agent's config no longer holds it.
