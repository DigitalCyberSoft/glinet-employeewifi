#!/bin/bash
# Build gl-sdk4-ui-empwifiview as an Architecture:all .ipk and an opkg feed index.
# Uses only tar + gzip + ar (no compiler, no SDK, no npm). Run on any Linux/macOS host.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PKG="gl-sdk4-ui-empwifiview"
VER="$(awk -F': ' '/^Version:/{print $2; exit}' "$HERE/pkg/control")"
OUT="$HERE/dist"
FEED="$HERE/feed"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DATA="$WORK/data"
CTRL="$WORK/control"
mkdir -p "$DATA" "$CTRL" "$OUT" "$FEED"

put() {  # put <src> <dest-relative-to-root>
	mkdir -p "$DATA/$(dirname "$2")"
	cp "$1" "$DATA/$2"
}

# --- payload tree ---------------------------------------------------------
put "$HERE/src/rpc/empwifi.lua"           usr/lib/oui-httpd/rpc/empwifi
put "$HERE/src/validator/empwifi.lua"     usr/share/gl-validator.d/empwifi.lua
put "$HERE/src/menu/empwifiview.json"     usr/share/oui/menu.d/empwifiview.json
put "$HERE/src/config/empwifi"            etc/config/empwifi
put "$HERE/src/nginx/empwifi.conf"        etc/nginx/gl-conf.d/empwifi.conf
put "$HERE/src/public/index.html"         usr/share/empwifi/www/index.html
put "$HERE/lib-upgrade-keep.d/$PKG"       lib/upgrade/keep.d/$PKG

# native admin view, pre-gzipped (host serves it via gzip_static)
mkdir -p "$DATA/www/views"
gzip -9 -c "$HERE/src/views/empwifiview.common.js" > "$DATA/www/views/$PKG.common.js.gz"

# i18n: emit every GL language from the English source so no locale shows raw keys
mkdir -p "$DATA/www/i18n"
for L in en de es it ja zh-cn zh-tw; do
	cp "$HERE/i18n/en.json" "$DATA/www/i18n/$PKG.$L.json"
done

find "$DATA" -type d -exec chmod 755 {} +
find "$DATA" -type f -exec chmod 644 {} +

# --- control --------------------------------------------------------------
cp "$HERE/pkg/control"   "$CTRL/control"
cp "$HERE/pkg/conffiles" "$CTRL/conffiles"
cp "$HERE/pkg/postinst"  "$CTRL/postinst"
cp "$HERE/pkg/prerm"     "$CTRL/prerm"
chmod 644 "$CTRL/control" "$CTRL/conffiles"
chmod 755 "$CTRL/postinst" "$CTRL/prerm"
printf 'Installed-Size: %s\n' "$(( $(du -sk "$DATA" | awk '{print $1}') * 1024 ))" >> "$CTRL/control"

# --- assemble ipk -----------------------------------------------------------
# OpenWrt .ipk = a gzip-compressed tar of debian-binary + control.tar.gz + data.tar.gz
# (NOT the Debian ar format). opkg detects the gzip outer and extracts.
tar --numeric-owner --owner=0 --group=0 -C "$DATA" -czf "$WORK/data.tar.gz" .
tar --numeric-owner --owner=0 --group=0 -C "$CTRL" -czf "$WORK/control.tar.gz" .
printf '2.0\n' > "$WORK/debian-binary"

IPK="$OUT/${PKG}_${VER}_all.ipk"
rm -f "$IPK"
tar --numeric-owner --owner=0 --group=0 -C "$WORK" -czf "$IPK" ./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $IPK ($(du -h "$IPK" | awk '{print $1}'))"

# --- feed index -----------------------------------------------------------
cp "$IPK" "$FEED/"
BASE="$(basename "$IPK")"
{
	grep -v '^[[:space:]]*$' "$CTRL/control"
	echo "Filename: $BASE"
	echo "Size: $(stat -c%s "$FEED/$BASE" 2>/dev/null || stat -f%z "$FEED/$BASE")"
	echo "SHA256Sum: $(sha256sum "$FEED/$BASE" | awk '{print $1}')"
	echo "MD5Sum: $(md5sum "$FEED/$BASE" | awk '{print $1}')"
	echo ""
} > "$FEED/Packages"
gzip -9 -c "$FEED/Packages" > "$FEED/Packages.gz"
echo "feed: $FEED/Packages(.gz)"
