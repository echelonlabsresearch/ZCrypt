#!/bin/sh
# Copies the brand source into the places that ship it. Run from the repository root.
set -e
cd "$(dirname "$0")/.."
mkdir -p wallet/src/brand
cp brand/tokens.css brand/fonts.css brand/logo-mark.svg brand/logo-tile.svg wallet/src/brand/
rm -rf wallet/src/brand/fonts && cp -R brand/fonts wallet/src/brand/fonts
SITE="${ZCRYPT_SITE:-../prelaunch-website}"
if [ -d "$SITE" ]; then
  mkdir -p "$SITE/brand"
  cp brand/tokens.css brand/fonts.css brand/README.md brand/logo-mark.svg brand/logo-tile.svg brand/logo-tile-square.svg brand/logo-lockup.svg brand/favicon.svg "$SITE/brand/"
  rm -rf "$SITE/brand/fonts" "$SITE/brand/png" && cp -R brand/fonts "$SITE/brand/fonts" && cp -R brand/png "$SITE/brand/png"
  cp brand/favicon.svg "$SITE/favicon.svg"
  cp brand/png/favicon-32.png "$SITE/favicon-32x32.png"
  cp brand/png/favicon-16.png "$SITE/favicon-16x16.png"
  cp brand/png/apple-touch-icon.png "$SITE/apple-touch-icon.png"
  cp brand/png/logo-tile-192.png "$SITE/icon-192.png"
  cp brand/png/logo-tile-512.png "$SITE/icon-512.png"
  echo "website synced: $SITE"
fi
echo "wallet synced"
