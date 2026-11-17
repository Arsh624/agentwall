#!/bin/sh
# Installs the latest agentwall release binary (Linux or macOS) into ~/.local/bin, verifying its SHA-256.
# Run: curl -fsSL https://raw.githubusercontent.com/Arsh624/agentwall/main/install.sh | sh
# Optional: AGENTWALL_VERSION=v0.1.0 pins a version, AGENTWALL_INSTALL_DIR changes the target directory.
set -eu

REPO="https://github.com/Arsh624/agentwall"
unsupported() {
	echo "unsupported OS, download a release from https://github.com/Arsh624/agentwall/releases" >&2
	exit 1
}

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) unsupported ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) unsupported ;;
esac

tag="${AGENTWALL_VERSION:-}"
if [ -z "$tag" ]; then
	tag=$(curl -fsSL https://api.github.com/repos/Arsh624/agentwall/releases/latest |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi
if [ -z "$tag" ]; then
	echo "could not determine the latest release (set AGENTWALL_VERSION=v0.1.0 to choose one)" >&2
	exit 1
fi

ver=${tag#v}
archive="agentwall_${ver}_${os}_${arch}.tar.gz"
base="$REPO/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
else
	echo "neither sha256sum nor shasum is installed, refusing to install an unverified binary" >&2
	exit 1
fi
expected=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
	echo "checksum mismatch for $archive, nothing was installed" >&2
	exit 1
fi

mkdir "$tmp/x"
tar -xzf "$tmp/$archive" -C "$tmp/x"
dir="${AGENTWALL_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$dir"
mv "$tmp/x/agentwall" "$dir/agentwall"
chmod +x "$dir/agentwall"

echo "installed $dir/agentwall ($("$dir/agentwall" --version))"
case ":$PATH:" in
*":$dir:"*) ;;
*) echo "add $dir to your PATH: export PATH=\"$dir:\$PATH\"" ;;
esac
