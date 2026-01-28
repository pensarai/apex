
set -e


REPO="pensarai/apex"
BIN_NAME="pensar"


INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"


OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) OS="darwin" ;;
  linux) OS="linux" ;;
  *) echo "❌ Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64) ARCH="x64" ;;
  *) echo "❌ Unsupported arch: $ARCH"; exit 1 ;;
esac

echo "➡️ Installing $BIN_NAME for $OS-$ARCH into $INSTALL_DIR"


JSON=$(curl -s https://api.github.com/repos/$REPO/releases/latest)


ASSET_URL=$(echo "$JSON" | grep browser_download_url | grep "$OS" | grep "$ARCH" | cut -d '"' -f 4)

if [ -z "$ASSET_URL" ]; then
  echo "❌ Could not find binary for $OS-$ARCH"
  exit 1
fi

echo "⬇️ Downloading $ASSET_URL"


TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"


curl -L "$ASSET_URL" -o pensar.tar.gz
tar -xzf pensar.tar.gz

if [ ! -f "./pensar" ]; then
  echo "❌ pensar binary not found in tarball"
  ls -la
  exit 1
fi

chmod +x ./pensar


mkdir -p "$INSTALL_DIR"
mv ./pensar "$INSTALL_DIR/pensar"

echo "✅ Installed pensar to $INSTALL_DIR/pensar"
echo "👉 Run: pensar --help"
