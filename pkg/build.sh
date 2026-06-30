#!/bin/bash
# Build gl-employee-wifi as an Architecture:all .ipk and an opkg feed index.
# Uses only tar + gzip + ar (no compiler, no SDK, no npm). Run on any Linux/macOS host.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PKG="gl-employee-wifi"             # opkg package name (what users install)
VIEW="gl-sdk4-ui-empwifiview"      # forced by GL's UI loader: /views/gl-sdk4-ui-<view>.common.js
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
gzip -9 -c "$HERE/src/views/empwifiview.common.js" > "$DATA/www/views/$VIEW.common.js.gz"

# i18n: emit every GL language from the English source so no locale shows raw keys
mkdir -p "$DATA/www/i18n"
for L in en de es it ja zh-cn zh-tw; do
	cp "$HERE/i18n/en.json" "$DATA/www/i18n/$VIEW.$L.json"
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

# Copy the landing-page screenshots into the feed (Pages publishes only feed/).
cp "$HERE/docs/screenshots/add-source.png" "$HERE/docs/screenshots/install-step.png" \
   "$HERE/docs/screenshots/admin-page.png" "$FEED/" 2>/dev/null || true

# Landing page so the feed's root URL isn't a bare 404 for humans (opkg only needs
# Packages.gz, but visitors and the user verifying the source URL see this instead).
cat > "$FEED/index.html" <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Employee WiFi - GL.iNet plugin</title>
<style>
  body{font:15px/1.65 -apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:980px;margin:0 auto;padding:40px 16px 64px;color:#222223}
  h1{margin:.2em 0}h2{margin-top:1.8em}code{background:#f2f2f7;padding:2px 6px;border-radius:4px}
  a{color:#5272f7}.muted{color:#6f6f71}
  img.shot{display:block;width:100%;margin:14px auto;border:1px solid #ebebf0;border-radius:10px}
  img.source{max-width:640px}
  ul{line-height:2}
</style>
</head><body>
<h1>Employee WiFi</h1>
<p class="muted">Let staff connect a GL.iNet travel router to guest WiFi - at a hotel,
conference, cafe, anywhere - from a simple page, no admin password, no advanced settings.
(<a href="https://github.com/DigitalCyberSoft/glinet-employeewifi">source on GitHub</a>)</p>

<h2>Install on your GL.iNet router (firmware 4.x)</h2>
<p>In the router's <b>Plug-ins</b> page, click <b>Manage Sources</b> and add:</p>
<ul>
  <li>Name: <code>empwifi</code></li>
  <li>URL: <code>https://digitalcybersoft.github.io/glinet-employeewifi</code></li>
</ul>
<img class="shot source" src="add-source.png" alt="Add Custom Software Source dialog" />
<p>Refresh the list, find <code>gl-employee-wifi</code>, and click <b>install</b>:</p>
<img class="shot" src="install-step.png" alt="gl-employee-wifi in the Plug-ins list with an install button" />
<p>It then appears in the admin under <b>Applications &rarr; Employee WiFi</b>:</p>
<img class="shot" src="admin-page.png" alt="Employee WiFi admin page" />

<p class="muted">Feed files: <a href="Packages">Packages</a> &middot;
<a href="Packages.gz">Packages.gz</a> &middot;
<a href="${PKG}_${VER}_all.ipk">${PKG}_${VER}_all.ipk</a></p>
</body></html>
HTML
echo "feed: $FEED/Packages(.gz) + index.html + screenshots"
