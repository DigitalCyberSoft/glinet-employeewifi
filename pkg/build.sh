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

# Landing page so the feed's root URL isn't a bare 404 for humans (opkg only needs
# Packages.gz, but visitors and the user verifying the source URL see this instead).
cat > "$FEED/index.html" <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Employee WiFi - opkg feed</title>
<style>body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;color:#222}code{background:#f2f2f7;padding:2px 6px;border-radius:4px}a{color:#5272f7}</style>
</head><body>
<h1>Employee WiFi - opkg feed</h1>
<p>This is the package feed for the <a href="https://github.com/DigitalCyberSoft/glinet-employeewifi">Employee WiFi</a> GL.iNet plugin. It is meant to be used by your router, not browsed.</p>
<h2>Install on your GL.iNet router (firmware 4.x)</h2>
<p>In the router's <b>Plug-ins</b> page, add a software source:</p>
<ul><li>Name: <code>empwifi</code></li>
<li>URL: <code>https://digitalcybersoft.github.io/glinet-employeewifi</code></li></ul>
<p>Then refresh and install <b>Employee WiFi</b>.</p>
<p>Feed files: <a href="Packages">Packages</a> &middot; <a href="Packages.gz">Packages.gz</a> &middot; <a href="${PKG}_${VER}_all.ipk">${PKG}_${VER}_all.ipk</a></p>
</body></html>
HTML
echo "feed: $FEED/Packages(.gz) + index.html"
