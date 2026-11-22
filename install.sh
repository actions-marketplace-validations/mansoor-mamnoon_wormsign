#!/bin/sh
# wormsign installer: downloads the latest release binary, verifies its
# checksum, and installs it. Read it before you run it — that's the point.
set -eu

REPO="mansoor-mamnoon/wormsign"
BIN_DIR="${WORMSIGN_INSTALL_DIR:-}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin|linux) ;;
  *) echo "wormsign: unsupported OS '$os' (on Windows, download the zip from GitHub releases)" >&2; exit 1 ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "wormsign: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

if [ -z "$BIN_DIR" ]; then
  if [ -w /usr/local/bin ]; then BIN_DIR=/usr/local/bin; else BIN_DIR="$HOME/.local/bin"; fi
fi
mkdir -p "$BIN_DIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/latest/download"
file="wormsign_${os}_${arch}.tar.gz"

echo "Downloading $file..."
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"

expected=$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "wormsign: checksum mismatch, refusing to install" >&2
  exit 1
fi

tar -xzf "$tmp/$file" -C "$tmp" wormsign
install -m 0755 "$tmp/wormsign" "$BIN_DIR/wormsign"
echo "Installed wormsign to $BIN_DIR/wormsign"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: $BIN_DIR is not on your PATH." ;;
esac
echo "Run: wormsign"
