# nzbd

**A private NZB indexer for you (or a small group you invite).** Drop your own `.nzb` files in a folder; nzbd indexes them, lets you search
them, explore their structure (files, segments, gaps) and download them again from a clean web page.

It never talks to Usenet and never makes an outbound connection. It is built to be small, boring and safe on your
own network.

Version **0.6.0** · Rust · SQLite or PostgreSQL · Tantivy ·
Docker · [changelog](docs/CHANGELOG.md)

**v3 starts a new library:** it does not upgrade a 2.x database (it refuses one and never touches it). Install it with a
new data directory and bring your NZB files over ([Quick install](docs/QUICK_INSTALL.md)).

![Index](docs/ui/index-chromium-light-1440.png)

## What it does

- **Collects** NZBs from a watch folder, a web upload form, or an upload-only API.
- **Indexes** title, date, size, category (Scene-name rules) and full text; designed for about a million releases,
  on SQLite (one container, the default) or PostgreSQL (the more secure choice for a shared install).
- **Explores** each NZB: files, segments, missing ranges, raw header.
- **Keeps you in control:** nothing is ever deleted automatically; deleting is explicit, confirmed and audited.
- **Protects itself:** password + mandatory TOTP per account (roles: viewer, uploader, admin) behind an optional Basic-auth proxy, hostile-input parsing, no egress.

## What it is not

A Usenet client, a Newznab/Torznab server for Sonarr/Radarr/SABnzbd, a read API, a public site with registration, or
something to put on the public internet. It is for one person or a small invited group on a trusted LAN: by default one
administrator account; with `security.multi_user = true`, invite-only uploaders and viewers share one library.

## Get started

| I want to... | Read |
|---|---|
| **Install it (guided, ~15 min)** | **[Quick install](docs/QUICK_INSTALL.md)** (`deploy/install.sh`) |
| Install it by hand | [Install guide](docs/INSTALL.md) |
| Use it day to day | [User guide](docs/USER_GUIDE.md) |
| Understand how it works | [How it works](docs/HOW_IT_WORKS.md) |
| Tune settings | [Configuration reference](docs/CONFIGURATION.md) |
| Back up, restore, upgrade, troubleshoot | [Runbook](docs/RUNBOOK.md) |
| Know which folders to keep and back up (the storage folder: plain host folders that `docker compose down -v` cannot delete) | [Install guide, section 10](docs/INSTALL.md#10-what-is-stored-where-folders-and-mounts) |
| Know what protects it | [Operator security notes](docs/OPERATOR_SECURITY.md) |
