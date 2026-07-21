#!/bin/sh
# Depfuse installer — one-liner for macOS/Linux
#
#   curl -sSfL https://raw.githubusercontent.com/falc0n-researcher/depfuse-oss/main/scripts/install.sh | sh
#
# Installs the latest release binary to /usr/local/bin (or $INSTALL_DIR).

set -e

REPO="falc0n-researcher/depfuse-oss"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY="depfuse"

# ── Detect OS and arch ───────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# ── Fetch latest release tag ────────────────────────────────
echo "→ Fetching latest release…"
TAG=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$TAG" ]; then
  echo "Could not determine latest release." >&2
  exit 1
fi

VERSION="${TAG#v}"
TARBALL="${BINARY}_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"

# ── Download and install ─────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "→ Downloading ${BINARY} ${TAG} (${OS}/${ARCH})…"
curl -sSfL "$URL" -o "${TMPDIR}/${TARBALL}"

echo "→ Extracting…"
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

echo "→ Installing to ${INSTALL_DIR}/${BINARY}…"
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi
chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "  ✓ ${BINARY} ${TAG} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "  Quick start:"
echo "    depfuse scan .                        # scan your project"
echo "    depfuse package express@4.17.1        # lookup a package"
echo "    depfuse cve CVE-2025-29927            # classify a CVE"
echo ""
