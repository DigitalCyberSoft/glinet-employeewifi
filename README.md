# Employee WiFi

A dead-simple page that lets staff connect a GL.iNet travel router to guest WiFi — at a
hotel, conference, cafe, anywhere — **no admin password, no advanced settings**. They scan,
tap a network, type its password, and they're online.

The employee page (`/wifi`):

<p align="center">
  <img src="docs/screenshots/wifi-login.png" width="32%" alt="Password gate" />
  <img src="docs/screenshots/wifi-networks.png" width="32%" alt="Pick a network" />
  <img src="docs/screenshots/wifi-connect.png" width="32%" alt="Connect" />
</p>

The admin page — a native entry in the GL.iNet admin (Applications → Employee WiFi):

<p align="center">
  <img src="docs/screenshots/admin-page.png" width="92%" alt="Admin settings page inside the GL.iNet admin UI" />
</p>

## What it does

- Adds a public page at **`/wifi`** for employees: scan → pick → password → connected.
- Adds an **Employee WiFi** page in the router admin (Applications) where you set the
  employee password, turn the password off, and toggle camouflage.
- Joins the chosen network as the router's uplink (repeater) with camouflage on.
- That's the whole feature. No band selection, no channels, no advanced WiFi settings.

## Install (the easy way)

It's a normal plug-in, served from this repo's GitHub Pages feed. On the router, open
**Plug-ins**, add a software source, then install:

- Name: `empwifi`
- URL: `https://digitalcybersoft.github.io/glinet-employeewifi`

<p align="center">
  <img src="docs/screenshots/add-source.png" width="72%" alt="Add Custom Software Source dialog (Plug-ins -> Manage Sources)" />
</p>

Refresh the list, find `gl-employee-wifi`, and click **install**:

<p align="center">
  <img src="docs/screenshots/install-step.png" width="88%" alt="gl-employee-wifi in the Plug-ins list with an install button" />
</p>

That's it. (Same thing from SSH if you prefer:
`echo 'src/gz empwifi https://digitalcybersoft.github.io/glinet-employeewifi' >> /etc/opkg/customfeeds.conf && opkg update && opkg install gl-employee-wifi`.)

> The feed is built and published automatically by `.github/workflows/publish.yml` (GitHub
> Pages, Source: GitHub Actions). Bump the version in `pkg/control` and push to republish.

## For the admin

Open **Applications → Employee WiFi**:

- **Set a password** staff type to open the `/wifi` page, or
- **No password required** for trusted setups, and
- **Camouflage** on by default (hidden behind a disguised MAC), where the device supports it.

## Requirements

- GL.iNet firmware **4.x** (the current web UI). Tested on the GL-XE3000; built
  architecture-independent (`Architecture: all`), so it runs on the wider 4.x family
  (Opal, Beryl, Slate, Flint, …). The installer stops cleanly on a device that can't run it.

## Built to stay small and simple

- **No build toolchain.** Lua + a little hand-written JS + JSON, packaged with `tar`/`gzip`.
  Rebuild with `./pkg/build.sh` — no npm, no webpack, no cross-compiler.
- **~13 KB** installed, **no background process**.
- **Survives firmware updates**: the package keeps its own files and settings across a
  "keep settings" flash.

## Security in one paragraph

The employee page is reachable by anyone on the router's LAN, so the password check, a
short-lived token, login rate-limiting, and strict input validation all live in the
backend — the page is never trusted. Employee actions can only scan and join a network;
they can never reach the router's advanced settings or admin RPC. Use "no password
required" only on networks you trust.
