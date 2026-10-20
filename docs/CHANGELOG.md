# Changelog

## 0.6.0 (2026-10-20)

### Added: categories and menu (T146)

New categories: **PC/Appz** and **PC/Games**, **Console/Microsoft**, **Console/Nintendo** and **Console/Sony**, and
**Books/Mangas**, and a new top-level **Mac** with **Mac/MacAppz** and **Mac/MacGames** (listed after PC). They can be chosen on upload, by `X-Category`, by watch sub-folder, by manual edit and in bulk edit; no
automatic rule files releases there. Audio already had MP3, Audiobook and Lossless. Existing libraries get the new
rows when nzbd starts (no migration). In the left menu, selecting a category now shows its sub-categories under it, and
XXX (when shown) is last in every category list.

### Added: NFO viewer

The NFO text is hidden by default: the release page shows the NFO card with a **Show NFO** / **Hide NFO** button (a
native `<details>`, no JavaScript) and the release index marks releases that have an NFO with an `NFO` badge (one
extra query per page). The release-group badge in the index now reads `Group <name>` (capital G). Families read `TV`, `Anime`, `Movie`, `Music` in the filter, chip and badges, and the Family filter gains a
`Game` entry (nothing is classified as Game yet).

Upload a release's `.nfo` together with its `.nzb` (same selection in the upload form, or an `nfo` part in
`POST /api/v1/nzb`) and the release page shows it as true DOS art: decoded from code page 437 (every byte its IBM PC
glyph, text stops at the DOS end-of-file mark so SAUCE records stay hidden), drawn with `line-height: 1` so box and
block characters join, with a full view, a UTF-8 switch and a **Download .nfo** link. NFOs pair with the NZB of the same
name (or with the only NZB of an upload), are at most 256 KiB, and can be added only by the release's uploader or an
administrator while the release has none; administrators can remove one. Stored in the database (table `release_nfo`,
migrations `v3/0011` and `v3-sqlite/0005`), so backups carry them; a deleted release keeps its NFO in the trash.
Audit events `nfo_attach` and `nfo_remove`. The API answer gains an `nfo` key only when an NFO was sent.

### Added: NFO next to an NZB in the watch folder (T141)

Drop `Foo.Bar-GRP.nfo` next to `Foo.Bar-GRP.nzb` in the watch folder and the NFO is attached when the NZB is ingested:
same name (exactly), `.nfo` in any letter case. It is attached only while the release has none (also when the NZB is
already known), audited as `nfo_attach` by `system` with `"source":"watch"`, and it follows its NZB: removed with it
once stored, moved with it to `failed/` or `duplicates/` (exactly the same generated name, `.nfo`), and carried along
by `nzbd failed retry`, expiry and purge. An NFO that is empty, larger than 256 KiB, or not attached for another reason
is never deleted: it goes to `failed/` (or `duplicates/`) as `<stamp>-<sha8>.nfo`, and the log names it. Every step
works relative to the NZB's own, verified directory; symlinks, hard-linked files, two NFOs or two NZBs differing only
by case, and anything that changed after it was read are never moved. An `.nfo` without its NZB stays where it is; an
`.nfo` is never ingested on its own.

### Decided: NFO text is never searchable

The owner abandoned T142 (2026-10-19): NFO content is display data only and is never put in the search index or used
by any filter.

### Hardening and fixes from public PR #1 (T143)

Contributed by Altansar69 (public PR #1, "Harden sessions, storage and downloads; fix UI and search reliability"),
ported onto 0.6 with the follow-ups of security review 55 (listed under each heading below).

#### Security

- Upgrade SQLx to 0.9.0, removing the optional vulnerable RSA dependency from the lockfile without enabling MySQL.
  The dependency audit no longer reports **RUSTSEC-2023-0071**.
- Password hashing and verification keep their concurrency slots until the blocking work actually finishes, even
  when a login or invitation request is cancelled. Cancelled waiters also leave the queue correctly.
- Downloads release their buffers and concurrency slots at the deadline even when a stalled client stops reading.
  Frames already handed to the HTTP connection retain only their chunk, not the entire NZB allocation.
- Upgrade Tantivy to 0.27.0 and its `lru` dependency to 0.18.5, fixing **RUSTSEC-2026-0253**.
- Reject non-whitespace text, CDATA and entity references outside the NZB document root, including after its closing
  tag. Opening stored blobs uses non-blocking, no-follow file access so a substituted FIFO cannot hang a reader.
- Cap the configured search offset window at its supported maximum, preventing oversized result allocations.
  Clippy now rejects Tantivy query APIs that bypass the bounded query builders.
- Invitation and recovery redemption revoke a presented old session in the same transaction as the new session.
  A revocation failure rolls everything back, preserving the code for a retry.
- Revoking sessions, API keys, invitations or recovery codes revalidates the calling session inside the mutation
  transaction, so a delayed request cannot use a revoked cookie to undo a later recovery.
- Sensitive account writes also refuse expired sessions that have not yet been purged, and a delayed session
  refresh cannot revive an expired cookie.
- Proxy error logs redact the complete request URI and Referer, covering tokens in arbitrary query parameters
  or path segments as well as the already protected authentication headers.
- Stored blobs refuse pre-existing symbolic links in either shard directory before reading, refreshing or deleting.
  Operator-configured links at the store root remain supported.
- Bulk archive timeouts retain concurrency slots until an in-flight storage read actually finishes.
- Quarantine purges respect the cleanup deadline and recheck the administrator's authority between batches.

#### Fixed

- SQLite backups lock their destination directory through cleanup, publication and rotation. Concurrent backups
  cannot remove each other's temporary snapshot, and cancelling the caller does not release the lock early.
  Filesystem and encryption work runs off the async runtime threads.
- Importing a duplicate repairs an existing corrupt blob even when its size matches the incoming file.
- A cancelled garbage-collection removal preserves a healthy blob published by a concurrent repair; the old copy
  remains in quarantine instead of overwriting the repair.
- PostgreSQL encrypted restore clears the actual temporary decryption file left by an interrupted restore.
- PostgreSQL backups also lock the destination directory through cleanup and publication. Cancelled exports
  release the lock without publishing a partial backup.
- Database errors during indexing preserve the outbox and discard uncommitted index changes for a clean retry.
- Upload category hints respect the current user's UI visibility; the upload API retains its documented ability
  to ingest categories hidden from the UI, for both header and multipart hints.
- Bound panic tracking when ingestion repeatedly encounters new failing paths. SQLite credential writers acquire
  their write transaction before reading, and failed-ingest lookups use a partial SHA index.
- Ingestion resumes correctly after index lag falls below half the configured threshold, including thresholds of
  one or an odd number.
- Expired sessions and pending MFA redirect the whole page during HTMX navigation (`200` + `HX-Redirect` for a
  `GET`; any other method gets `401` + `HX-Redirect`, so a refused write is never a success). Empty search results
  keep a valid swap target, and filters stay synchronized after sorting or navigating back.
- Network errors, timeouts and failed HTMX requests display an accessible message. The select-all checkbox reflects
  partial selection and restored pages; sorting and select-all remain usable on mobile. Email fields use the same
  styling as other inputs, and viewer empty states no longer suggest an upload they cannot perform.
- Selection actions stay disabled until a release or file is checked. Without JavaScript, empty submissions show a
  readable HTML error page with navigation; API requests continue to receive JSON errors.
- Enter in the bulk source field submits the source action when JavaScript is available. Ambiguous implicit bulk
  submissions are blocked; without JavaScript, the explicit action buttons remain usable.
- Proxy examples allow a complete web upload batch (321 MiB) while keeping the API request limit at 65 MiB.
  The nginx example preserves the port in the `Host` header so origin validation works on non-default ports.
- Refresh the CSS and JavaScript asset hashes, and make the installer and PostgreSQL bootstrap assignments explicit
  for shell linting.

#### Changed

- Filtered release lists skip the unused ingest-timeline database query. Statistics dictionary decoding uses bounded
  batches to preserve query deadlines with Tantivy 0.27.
- Expand regression coverage for cancellation, stalled downloads, backup concurrency, blob repair, malformed NZBs,
  index upgrades, SQLite outbox transactions and restore credential revocation. The legacy SQLite check fixture is
  generated from migrations, and source-bundle tests run without the separate fuzz project when
  `NZBD_SOURCE_BUNDLE=1` is set (anywhere else a missing `fuzz/` fails the SEC-089 scan).
- Exercise both historical database migration paths on every test run: saved-search and page-size migrations
  preserve populated 3.1 data, and the subsequent roles migration refuses it with `FRESH_DATA_REQUIRED` without
  altering that data or the successful migration ledger, including on retry. This does not enable an unsupported
  populated-library upgrade across the roles boundary.
- Cover MFA enrollment confirmation over HTTP with missing, invalid, malformed and expired enrollment tokens,
  checking that neither a new nor an existing pending secret is disclosed. A valid-token control verifies QR setup.

#### Follow-ups of security review 55

- The blob store's garbage collection falls back to a no-clobber rename on filesystems without hard links, and a
  leftover GC file under a shard directory that became a symlink no longer stops nzbd from starting.
- A release whose document can never be loaded no longer stalls the search index: after 8 failed rounds in a row the
  batch is split per document, the rest is indexed, and that release is quarantined after its retries.
- A login refused because the password changed at the same moment is audited (`login.fail`, `credentials_changed`).
- A PostgreSQL restore removes its decrypted scratch file on every decryption error.
- SQLx uses only the bundled SQLite driver features of 0.8 (no extension loading, no `deserialize`).
- The nginx example streams `/upload` to nzbd (`proxy_request_buffering off`).

### Fixed: "Uncategorized" badge after a manual category (T148)

A release whose category was set by hand (single or bulk edit) no longer shows the **Uncategorized** badge and no longer
matches the `uncategorized` flag filter: the edit clears the flag, and rows overridden earlier are masked when shown and
when indexed. Documents indexed before this change refresh on their next reindex or edit.

### Upgrading

**Reverse proxy:** nzbd now closes a keep-alive connection that stays idle for 10 s (also its header deadline). The
bundled Caddy drops idle upstream connections after 8 s. With your own proxy, set the same (Traefik:
`serversTransport.forwardingTimeouts.idleConnTimeout: 8s`; Caddy: `transport http { keepalive 8s }`; nginx keeps no
upstream connection by default), and allow 321 MiB on `/upload` and 65 MiB on `/api/v1/nzb`. Proxy logs redact the
whole request URI. See DEPLOYMENT "Keep-alive and header deadline".

The new migrations (`v3/0011`, `v3-sqlite/0005` and `v3-sqlite/0006`) run like every other one (`setup` on
PostgreSQL, at start on SQLite). A 0.5 binary refuses the upgraded database; to roll back, restore the backup taken
before the upgrade.

The search index schema is now **3**. On the first opening after this upgrade, nzbd automatically rebuilds an older
index from the database. Search stays in degraded mode until the rebuild finishes; allow time for large libraries.
The database and stored NZB files are retained, and no manual index deletion is required.

### Dependency audit status

SQLx 0.9.0 makes MySQL RSA authentication opt-in. The application does not enable MySQL, and `Cargo.lock` no longer
contains `rsa`. `cargo audit` passes without advisory suppressions.

## 0.5.1 (2026-10-18)

### Changed: one storage folder (bind mounts, no Docker volumes)

Everything nzbd keeps lives in plain bind-mounted host folders under one **storage folder** that the installer asks for
(default `deploy/storage`): the library in `data/` and, next to it, `secrets/` (TOTP key, backup key, database
passwords), `state/` (`paths.state`), `caddy/` (the proxy's CA and certificates) and, with PostgreSQL, `setup_secrets/`
and `pg_secrets/`. With PostgreSQL the installer also asks for the database folder (default `<storage folder>/pg_data`).
`.env` holds `NZBD_DATA_DIR`, `NZBD_VOLUMES_DIR` and `NZBD_PG_DATA_DIR`. `docker compose down -v` and `docker volume prune`
cannot delete any of it. Compose never creates the folders (`create_host_path: false`); `volperms` hands them to their
users. The only named volume left is the PostgreSQL socket directory.

An earlier install that kept its keys in Docker volumes must copy them once, with the old stack stopped
(`docker compose stop`, never `down -v`), before deploying: otherwise the new stack starts with an empty key folder, a
NEW TOTP key, and nobody can log in. `install.sh` stops and prints the command when it finds such volumes. Per volume
(`nzbd_nzbd_secrets` or `nzbd_secrets` -> `secrets`, `nzbd_nzbd_state` or `nzbd_state` -> `state`, `nzbd_caddy_data` or
`nzbd_caddy` -> `caddy`; PostgreSQL: `nzbd_nzbd_setup_secrets` or `nzbd_setup_secrets` -> `setup_secrets`, `nzbd_pg_data`
-> the database folder, `nzbd_pg_secrets` -> `pg_secrets`):

```
mkdir -p storage/secrets && docker run --rm -u 0 -v nzbd_nzbd_secrets:/from:ro -v "$PWD/storage/secrets":/to \
  --entrypoint sh caddy:2 -c 'cp -a /from/. /to/'
```

Then re-run `./install.sh` (keep the existing `.env`; it asks for the folder of the keys once). Remove the old Docker
volumes yourself once the new stack works.

### Changed: installer

- **Readable logs by default.** The stack now runs nzbd with `NZBD_LOG_FORMAT=pretty` (coloured lines and a startup
  banner in `docker compose logs`); set `NZBD_LOG_FORMAT=json` in `deploy/.env` for log shippers.
- Running Traefik containers are listed first and recommended; for any other proxy every Traefik question is skipped.
- `install.sh` refuses to run with `compose-example/` or `volperms.sh` from another release.
- Every dev and test container and volume starts with `dev_` (`scripts/dev`, the gates), so none can be mistaken for a
  real install on the same host.

### Fixed

- The pinned hash of `app.css` (served as its ETag) matches the file again (the 0.5.0 comment edit had drifted it).

## 0.5.0 (2026-10-17)

**Renumbered (owner decision): the project restarts its version line at 0.5.0** in this repository
(copied from the earlier `newznab-fork` checkout at commit ff37f30). 0.5.0 is 3.5.0 plus
the faster gates below; the program is otherwise the same as 3.5.0. The older tags (v1.x to v3.5.0) were removed here;
the entries below keep their original numbers as history. **Fresh data required**, as for 3.5.0. Security review:
section 51 (no Critical/High/Medium; Lows fixed).

### Changed: short fixed container names

Long-running containers have short fixed names (`nzbd`, `nzbd-proxy`, `nzbd-db`); `NZBD_NAME_PREFIX` (default `nzbd`)
changes the prefix. (0.5.0 kept the keys in Docker volumes `nzbd_secrets`, `nzbd_state`, `nzbd_caddy`; 0.5.1 moves them
into the storage folder.)

### Added

- **Upload and delete audit trail (T138).** New audit events `nzb_upload`, `nzb_upload_dup` and `nzb_upload_reject`
  (UI form and `POST /api/v1/nzb`, attributed to the user or the API key's owner, written after the ingest commits);
  `release_delete` now also records the title and the original uploader. New admin-only **Activity** page
  (`/admin/activity`) with user, event and date filters and paging; other roles get the uniform 404. Security review:
  section 52 (no Critical/High/Medium).
- **Readable container logs (T137).** `NZBD_LOG_FORMAT=pretty` prints coloured single-line logs and an ASCII banner;
  JSON stays the default. `NO_COLOR=1` removes the colour.

### Fixed

- **Release group (PARSER_SPEC decision 10).** The last `-` part of a name is the group even when the family is not
  recognised (`Toto.Pc.Game.299133-Mephisto` gives `Mephisto`).
- **Users page.** The "Active" badge is replaced by Online (a session seen in the last 5 minutes) or Offline, and the
  status badges stay on one line.

### Changed

- **Faster gates (T136, owner request 2026-10-17; development tooling only, the app is unchanged).** On a Docker VM
  with at least 6 CPUs and 15 GiB, `scripts/dev ci` runs its independent stages concurrently (build and clippy, fuzz
  check and deny/audit; then the four test legs, online and offline, each container on its own test Postgres; then the
  timing-sensitive tests alone) and `scripts/dev browser-check` runs its SQLite and PostgreSQL legs at once. Same
  checks, same pass/fail rules, output printed per stage in a fixed order. Smaller VMs (the 8 GiB Docker Desktop
  default) keep the sequential order; `GATES_PARALLEL=0|1` forces either. The test Postgres now times out an
  abandoned authentication after 10 s instead of 60 s, which removes up to a minute of idle waiting per affected test
  binary on machines with few CPUs.

## 3.5.0 (2026-10-17)

**Owner requests: roles viewer / uploader / admin (T134, D40) and a configurable, hidden invitation path (T135).**
Security reviews: sections 49-50 (no Critical/High/Medium; Lows fixed). Full gate set (CI, browser check, e2e,
deploy check) on the integrated tree.

**Fresh data required** (owner rule during development) for the roles change below: the role CHECKs of the database
changed (new migrations `v3/0010_roles.sql` and `v3-sqlite/0004_roles.sql`); there is no conversion of `member`
accounts and no upgrade path. Both backends refuse to apply the migration to a library that already holds accounts,
invitations, audit rows or an audit chain head: SQLite at startup, PostgreSQL in `nzbd db migrate`, each with an
error that names `FRESH_DATA_REQUIRED`. Start from a new library.

### Changed

- With `security.multi_user = false` a POST to the (unmounted) invitation path is now classified like any unknown path
  (UI rate class, no early `413`) instead of the login class (T135).

- **Roles: viewer / uploader / admin (T134, owner request, D40).** The role `member` is renamed **`uploader`** and no
  longer edits metadata: changing the category or source label of a release (on the release page or for several at once
  from the result list) is now **admin-only**, also for an uploader's own uploads; an uploader that tries gets the same
  "Not found" page as any unknown address. Uploaders keep the upload form, `POST /api/v1/nzb` with their own API keys
  and the API-key section of the Account page; viewers keep downloads (single, selected files, several releases as a
  zip), saved searches, statistics and their preferences. The bar under the result list shows a viewer and an uploader
  only **Download selected (.zip)**; an admin also gets the category/source edits and **Delete selected...**. The
  invitation form and the role change on the Users page offer **Uploader** and **Viewer**; administrators are still
  created only with `nzbd user create --role admin`. On the command line `--role member` is refused with
  `ROLE_RENAMED: use uploader`.
- **Demoting to viewer revokes the account's API keys** (T134 review I5). A role change to `viewer` (Users page or
  `nzbd user set-role`) revokes every unrevoked API key of that account in the same transaction; the `role_change` audit
  row says how many (`keys_revoked=<n>`). A viewer cannot use a key anyway; this removes the dormant keys so a later
  promotion does not silently revive them.
- The index's "Latest ingests" card shows its **Full ingest log** link to administrators only (it led other roles to
  "Not found").

### Added

- **Configurable (hidden) invitation path (T135, owner request).** New setting `security.invite_path` (default
  `/invite`; env `NZBD__security__invite_path`), e.g. `"/join-7f3k9q"`: the anonymous invitation page is then served
  there only, and `/invite` is the same 404 as any unknown path. Validated at startup and by `nzbd config check`
  (`INVITE_PATH_INVALID`: `/` plus one segment of 6-64 `A-Z a-z 0-9 _ -`, never a built-in route or a prefix of one,
  checked against the route inventory). The page keeps everything `/invite` had (one-time code, login rate class, its
  own Argon2 queue, CSRF, recovery codes). The path is never shown on an anonymous page, and the login page no longer has the
  "Have an invitation code?" link in any configuration (invitees use the address handed over with the code); the admin invitation/recovery result pages, `nzbd user invite` and
  `nzbd config check` print it as the full address to hand out (`server.public_url` or the first allowed host plus the
  path; the path alone otherwise). `deploy/install.sh` writes a random `/join-` + 12 character path into a fresh
  `config/nzbd.toml` and prints it; existing settings files are never changed. Obscurity only: it keeps scanners off the
  page, the one-time code remains the protection and the proxy login stays recommended (OPERATOR_SECURITY). Values
  starting with `invite` (other than `/invite`) are refused; `config check` and startup warn while multi-user mode keeps
  `/invite` (`INVITE_PATH_DEFAULT`) or a custom path is under 10 characters (`INVITE_PATH_SHORT`). The e2e
  journey and the browser check run in multi-user mode with a custom path.


## 3.4.0 (2026-10-17)

**Owner requests: statistics page (T132) and items per page (T133).** Security reviews: sections 47-48 (no
Critical/High; Mediums and Lows fixed). **Fresh data required** (owner rule during development): `user_pref` gains
two columns (migrations `v3/0009`, `v3-sqlite/0003`). Release gate for this version: CI only (owner decision); the
full gate set runs at 3.5.0.

### Added

- **Items per page (T133, owner request 2026-10-17).** A small **Per page** control (select + **Show**) at the bottom
  right under the release list (25 / 50 / 100; 50 by default, capped at the bulk-action maximum of 100) and under a
  release's files table (50 / 100 / 250 / 500; 100 by default). The choice is remembered per account and is also on
  Account > Preferences ("Rows per page"); changing it keeps the search, filters and sort and returns to page 1. Any
  other value is ignored. The control is a CSRF-protected POST (`POST /page-size`, at most 6 changes per account
  and minute, audited as `pref_change` with key names only); it works without JavaScript. **Schema change, fresh data
  required** (owner rule): `user_pref` gains `page_size_releases` and `page_size_files` (migrations Postgres
  `0009_page_size`, SQLite `0003_page_size`); no upgrade path is promised for this change.
- **Statistics page (T132, owner request).** `Statistics` in the sidebar and the phone Menu opens `/stats`, for every
  role: overview tiles (releases, total size, added in the last 7 and 30 days), releases per category as the taxonomy
  tree with total and average size, the top 10 release groups (each links to the index filtered by that group) with
  the number of releases without a group, a quality breakdown (resolution, source, family, top 10 years, "Unknown"
  shown) and releases added per month over the last 24 months. Every number is per account: hidden categories
  (instance and "Hide XXX for me") are left out everywhere, including the group list. Per-category numbers come from
  the exact category totals (no scan); the rest from bounded aggregations of the search index under the search
  deadline. Refreshed every 10 minutes; a section that cannot be computed in time says so and the rest of the page is
  shown. Server-rendered CSS bars with exact numbers as text, no JavaScript, no chart library, CSP unchanged.
## 3.3.0 (2026-10-17)

**Owner requests: stat tiles back (T129), download from the result list incl. ticked releases as one zip (T130),
title from the .nzb file name and search on file name and release group (T131, D39).** Security reviews: sections
45-46 (no Critical/High/Medium; Lows fixed). **Fresh data required** (owner rule during development): the search
index schema changed (version 2) and titles are decided differently; no migration or re-index tooling.

**Search finds the `.nzb` file name and the release group; the title prefers the file name (T131, owner bug report
and decision D39, 2026-10-17).** Fresh data required (owner rule): there is no migration, re-title or re-index batch;
the search index schema is version 2; an index of version 1 is refused by the existing schema check (start from
fresh data).

### Added

- **Download from the result list (T130, owner request 2026-10-17).** Every row of the index and of search results has a
  small **Download** button for that release's NZB (the same `GET /release/{id}/download` as the release page; every
  role). Tick releases and press **Download selected (.zip)** in the bar under the table to get them as one file
  `nzbd-<n>-releases-<yyyymmdd-hhmmss>.zip` (UTC): one `<title>.nzb` per release (the allowlisted download name; a
  second release with the same name gets `-<id>`), the stored NZBs byte for byte, uncompressed. Up to 100 releases and
  1 GiB of NZB data per zip (`TOO_MANY_IDS`, `BULK_DOWNLOAD_TOO_LARGE`); releases deleted meanwhile or hidden from you
  are left out (none left: "not found"). Viewers now see the checkboxes too, with only this action; the edits stay
  member-only and the delete admin-only. New route `POST /releases/bulk/download` (viewer and up, session + CSRF).
  One bulk download runs at a time, and one per account (`503 BUSY`, `Retry-After: 30`, free of the per-minute
  budget), two per minute per address and per account on top of the download limits (`429`), streamed one NZB at a
  time with a send deadline of 60 s + 1 s/MiB (at most 4 min 30 s, below the shipped proxy's 5-minute write timeout:
  on a slow link tick fewer releases) and a minimum speed (256 KiB per 30 s after the first 30 s); a corrupt stored
  NZB, the deadline or too slow a reader breaks the download off instead of producing an incomplete zip, and a
  release deleted meanwhile is left out. Audit event `download_bulk
  count=<n>` (attributed to the account). New direct dependency of `nzb-web`: `crc32fast` (already in the build
  through tantivy). No database change.

### Fixed

- **Search finds words of the `.nzb` file name and the release group.** Searching `Mephisto` now finds a release
  uploaded as `toto.PcGame-Mephisto.nzb` even when its title came from the inner files or the NZB metadata, and a
  release group (`-GRPNAME`) is found by free text, not only by the group filter. New analyzed index field
  `source_name` (the file name without `.nzb`, plus the parsed group), matched like the title, file names and poster,
  with the same prefix and typo-fallback behaviour; hidden categories stay excluded.

### Changed

- **The stat tiles are back on the index (T129, owner request).** Releases, Segments and Total size (Incomplete only
  with a health check) sit again as tiles above the search card, replacing the 3.1 one-line summary next to the title.
  Same numbers as before (per account: hidden categories, instance and "Hide XXX for me", are left out) from the same
  cached read. Restyled to the 3.1 palette: flat neutral panels, a calm blue glyph, no green; one row on desktop, a
  compact row on phones so the search box stays on the first screen. No JavaScript, CSP unchanged.
- **The release title prefers the `.nzb` file name.** Fully obfuscated NZBs (random inner names, no metadata) now get
  the name of the file you dropped or uploaded as their title. The file name is used only when it is usable: not a
  generic browser name (`download`, `download (1)`, `nzb`, `file`, `get`, `index`, `api`, `untitled`), not digits
  only, not hash-like (DECISIONS D39 has the exact rule); otherwise the NZB metadata title, then the title derived from
  the inner files. The usable file name is also the first name the Scene rules look at. A duplicate under another file
  name keeps the existing title.
- **An XXX category hint wins over the Scene rules.** A watch rule, sub-folder or upload/API category inside XXX now
  keeps the release in XXX even when its name looks like a movie or TV release, so it stays hidden from users who hide
  XXX (other hints still lose to a conclusive Scene result).

## 3.2.1 (2026-10-17)

**Installer: nzbd runs as the installing user's UID:GID (T128, owner request; SECURITY_REVIEW section 44).** No
database change: a 3.2.0 library opens unchanged. Fresh installs only (owner decision): the installer does not migrate
an existing deployment's ownership; a key volume owned by another user is refused with the fresh-start step.

### Added

- **The installer runs nzbd as your user (T128).** `deploy/install.sh` asks which numeric UID:GID nzbd runs as and
  proposes the account running it (`id -u`/`id -g`; through `sudo`, the caller's `SUDO_UID`/`SUDO_GID`; as root, the
  image's own `10001:10001`). Enter accepts, or type another `UID:GID`; `0` (root), single numbers, names, signs,
  blanks, leading zeros and values above 2147483646 are refused and asked again. Stored as `NZBD_UID` / `NZBD_GID` in
  `deploy/.env` (re-validated on every run; a non-interactive render refuses a `.env` without them), shown by
  `--print-compose` and the summaries. The data directory, the TOTP key and the other nzbd volumes belong to it, so
  you can manage `data/` without sudo. `nzbd`, `keygen` and `setup` run as `user: "${NZBD_UID:-10001}:${NZBD_GID:-10001}"`
  in every compose template; PostgreSQL (999) and the proxy (65532) are unchanged.
- Security review 44 fixes: nzbd makes itself **non-dumpable** first thing (every subcommand), so a host process of
  the container user's uid cannot read the TOTP key, the database passwords, the environment or the memory through
  `/proc/<pid>/...`; the SEC-042/SEC-102 owner checks take the uid from `geteuid` (the owner of `/proc/self` is root
  for a non-dumpable process). `serve` and the other root-refusing commands also refuse group 0. UIDs/GIDs 999
  (PostgreSQL's superuser by peer authentication), 65532 and 65534 are refused. Rootless Docker / userns-remap is
  detected (proposal 10001:10001). The data-directory helper runs like `volperms` (CHOWN, DAC_OVERRIDE, FOWNER only)
  with nzbd stopped.
- New one-shot compose service `volperms` (profile `setup`; the Dockerfile.proxy Caddy digest as root with only
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, no network, read-only) hands the new named volumes to that user before `keygen`;
  `dbsecrets` writes the nzbd secrets for it.

### Read first

- **Fresh installs only** (owner decision 2026-10-16): there is no migration of an existing install to another user.
  Key volumes holding files of another UID:GID are refused with a fresh-start explanation; nzbd never re-owns or
  deletes them. A kept `.env` without `NZBD_UID`/`NZBD_GID` is asked the question like a new install.
- No new outbound connection, no new dependency, no change to the nzbd binary.

## 3.2.0 (2026-10-16)

**Three small improvements (owner-approved, D38): partial NZB download (T125), watch-folder rules (T126) and saved
searches with a "new since last visit" badge (T127).** Security reviews: SECURITY_REVIEW sections 41-43 (no Critical
or High; every Medium and Low fixed before merge).

### Read first

- **Database change (one new table, `saved_search`).** Migrations: PostgreSQL `v3/0008_saved_search.sql`, SQLite
  `v3-sqlite/0002_saved_search.sql`, applied at the first start. A 3.1 binary refuses the 3.2 database as a newer
  schema. **Take a snapshot before upgrading; rollback = restore that snapshot and reinstall 3.1.0** (unlike 3.1,
  reinstalling the previous version alone is not enough). See RUNBOOK.
- **New configuration (optional):** `[[ingest.rules]]` (see CONFIGURATION "Watch-folder rules"). An invalid rule
  refuses startup with a stable `RULE_*` code; with no rules, ingest behaves exactly as in 3.1.
- No new outbound connection, no new dependency (the `regex` crate already shipped with `nzb-core`), CSP unchanged,
  no JavaScript added.

### Added

- **Partial NZB download (T125).** On a release page, tick files and press **Download selected** to get
  `<title>-partial.nzb` with only those files (for example the `.mkv` and its `.par2`, without samples). The NZB is
  rebuilt from the stored, SHA-256-verified copy by the hardened parser and an escaping serializer; the stored file is
  never changed. `POST /release/{id}/download/selected` (session, CSRF, same role and download rate limits as the full
  download); refusals `NO_FILES_SELECTED`, `BAD_FILE_INDEX`, `PARTIAL_TOO_LARGE`; one partial download at a time
  (DEPLOYMENT "Memory budget": about 288 MiB for downloads in the worst case); audit event `download_selected`.
  Selection is per files page (100 files).
- **Watch-folder rules (T126).** Operator rules map a first-level watch sub-folder (`subfolder = "..."`) or a
  file-name pattern (`filename = '<regex>'`) to a category hint and/or a source label; first match wins, an explicit
  rule beats `category_from_subfolder`, scene detection still wins over a hint, duplicates are never relabelled, UI/API
  uploads and `nzbd import` are unaffected. `nzbd watch rules` is a read-only dry run of what each file in the watch
  folder would get (refuses root unless `--allow-root`). The ingest log records `rule=N`.
- **Saved searches (T127).** Save the current index search (text and filters) under a name; the index sidebar (and
  the phone Menu) lists your saved searches with an "N new" badge for releases ingested since you last opened each one
  (capped at 99+, counted within a 150 ms page budget, hidden categories never counted). Manage them at
  `/search/saved` (rename, delete). Private per user, up to 25, unique names (`SAVED_SEARCH_LIMIT`,
  `SAVED_SEARCH_DUPLICATE`, `SAVED_SEARCH_NAME`); stored as validated filters and re-checked on every use; included in
  backups and snapshots; not audited (they are private, like the theme).

### Changed

- Search text and group filters drop bidi controls and invisible format characters (the same set the ingest title
  sanitizer removes), so a pasted query matches the indexed title.
- Admin audit table: the Event column wraps.

### Fixed (tests)

- `sec_026` concurrent-burst test asserted an order the design does not promise (a correct password decided before the
  fifth failure is the fifth allowed guess). Replaced by tests of the real invariant (at most five guesses decided
  before the lock, nothing accepted after it), incl. a 16-request burst; no auth code changed.

## 3.1.0 (2026-10-16)

**A visual-polish release (T124, owner-approved as 3.1 "so we can revert").** Templates and the stylesheet only.

### Read first

- **No database change.** 3.1 has no migration, no schema change and no new stored preference: a 3.1 library is a 3.0
  library. **Rollback = reinstall 3.0.0** on the same data directory (and the same backend); nothing to undo or
  migrate. No route, form field, configuration key or JavaScript was added; CSP, escaping, CSRF, the hidden-XXX rules
  and the uniform 404 are unchanged.

### Changed (web UI)

- **Index list, calmer rows.** The original file name under a title is shown only when it differs from the title (it
  was usually the title plus `.nzb`); the completeness percent and bar only when segments are missing (never today:
  there is no news-server check); the category badge only for **Fallback** and **Manual** ("Scene" on every row is
  gone; the release page still names it); the **Source** cell is one line (the label, else *Watch folder* / *Upload* /
  *API* in grey) with "..." instead of mid-word wrapping and the full value plus origin on hover; **Posted** reads
  "12 months ago (2025-10-09)".
- **One summary line instead of the three stat tiles:** "68 releases · 1,578 segments · 1.0 GiB" next to the page
  title (same numbers, per caller, hidden categories excluded).
- **One search row:** text, category and **Search**; **More filters** folds open below it; the second "Apply filters"
  button is gone (Search applies everything). **Clear filters** sits next to Search while filtered.
- **Sidebar counts:** on the index page each Browse category shows how many releases it holds, from the existing exact
  per-category totals; categories hidden for the instance or for you are never counted.
- **Release page:** **Delete release** moved away from **Download NZB** into a **Danger zone** at the bottom of the
  Edit panel (admins); the Alerts panel is blue for information only (for example Par2), orange for attention, red for
  a problem; Posted and Indexed read "3 days ago (2026-10-13 08:12 UTC)"; the files table's column is now
  **Completeness** (was "Bar") and appears only when a file of the page has gaps, with bars on those files only; the
  summary meter only when segments are missing.
- **Phone (< 768 px):** the navigation folds into a CSS-only **Menu** button in the top bar (a `<details>` element, no
  JavaScript), so the search box is on the first screen.
- **Colours (light and dark, also the forced themes):** links and primary buttons use a calm blue with a quiet
  underline that darkens on hover; green is kept for "active / OK" only (current menu entry, OK badges); panel headings
  use the text colour and light panels have a slate top line. Every text colour pair keeps at least 4.5:1 contrast
  (unit test extended).
- Not in 3.1: the compact / comfortable density switch (SUGGESTIONS U15) needs a stored preference, so it waits for a
  later version.
- Screenshots in `docs/ui/` (also new: `index-menu-chromium-light-390.png`, the open phone menu). docs/UI_SPEC.md
  "Visual polish (3.1, T124)", UI_NOTES, USER_GUIDE.

### Changed (tooling only; the app and the images are unchanged)

- **The real-browser check fails fast instead of hanging** (`scripts/dev browser-check`, nightly). Every Playwright
  action and navigation is bounded (`BROWSER_ACTION_TIMEOUT_SECS`, default 30 s), so are the sign-in, each journey step
  (`BROWSER_STEP_TIMEOUT_SECS`, 180 s) and the screenshot matrix step (`BROWSER_MATRIX_TIMEOUT_SECS`, 420 s); a hang is
  reported as `TIMEOUT [<engine>/<backend>] step ... at <page> (<scheme> <width>px)`. The script also enforces a
  wall-clock limit per backend leg (`BROWSER_TIMEOUT_SECS`, 900 s): the browser container is killed, the leg shows as
  `TIMEOUT` and the run exits non-zero. No retry: a timeout is a failure. The per-run browser image now uses a gate tag
  (`nzbd-browser:gate-<pid>`) instead of a `:local` one. docs/TESTING.md "Real-browser check".

## 3.0.0 (2026-10-16)

**Status: release candidate.** The T118 security audit is done (SECURITY_REVIEW section 39: ship after fixes, no
Critical or High; the fixes are in "Fixed" below); it waits for the owner's approval and is not tagged, pushed or
published. The version may be renumbered for the first public release (D37 e). v3 is the definitive line
("v3 is the real v1", D37 a): its whole validated scope ships, no reduced cut.

### Read first

- **Fresh start, no upgrade from 2.x (D37 b).** nzbd 3 starts a **new library**. A 2.x (or older) database is refused
  with `LEGACY_DATABASE` and **never modified** (not migrated, not chmod-ed, no sidecar file left behind;
  `legacy_database` tests prove 0.1.0, 1.1.0 and 2.0.0 files stay byte-identical). Install 3.0 next to 2.x with a
  **new data directory** (the installer detects a 2.x `.env`, keeps it as `.env.bak.<time>` and refuses the old data
  directory), create the accounts again, then refill the library with **`nzbd import <dir>`** (or copy the NZB files
  into the new watch folder). Keep the 2.x data directory and a 2.x backup until you no longer need them; the 2.x
  images still run them. RUNBOOK section 5.
- **Choose the database backend once, at install (D35 b, D37 c).** `./install.sh` asks: **SQLite** (the default: one
  container, nothing else to run; fine for a personal library on a LAN) or **PostgreSQL** (two more containers;
  **recommended for a shared or internet-facing install**, because a compromised nzbd process then cannot rewrite the
  audit history, purge before the retention floors or delete accounts). Both serve the same features and are fully
  tested in CI and in every release gate. The choice is **final** for a library: nzbd refuses a switched configuration
  (`BACKEND_MISMATCH` / `LIBRARY_MISMATCH`), and moving a SQLite library to PostgreSQL is **deferred** (D37 d).
  OPERATOR_SECURITY "Choosing a backend".
- **Performance is designed, not measured.** The ~1M-release budgets (D35 a: search and listing p95 <= 250 ms, ingest
  >= 500 NZBs/s, index lag p95 <= 2 s, rebuild <= 10 min, per backend) are the design target; the 1M benchmark on both
  backends (T117) is **planned and has not been run** (benchmarks run only on owner request). T114 is built but not
  ticked for that reason.
- **A 2.x configuration file is not accepted as is.** Removed keys are refused as unknown (`db.durable`,
  `maintenance.log_retention_days`, `maintenance.account_audit_retention_days`), and `store.backend = "db"` is refused
  with `STORE_DB_BACKEND_REMOVED`. The installer creates a fresh `deploy/config/nzbd.toml`.

### Added

- **Two database backends behind one storage seam** (T111, T112, T121, T122; D33, D35, D36): `db.backend = "sqlite" |
  "postgres"`. The SQLite line starts from a clean v3 baseline schema (`migrations/v3-sqlite/`), PostgreSQL from
  `migrations/v3/` (partitioned `release`/`nzb_file`, keyset pagination, a superuser bootstrap in
  `migrations/v3/superuser/`). The same invariants live in both databases (last-admin trigger, no-row-delete and
  immutable audit rows in every column, retention floors 90 / 365 days as CHECKs, invite and session CHECKs; a schema
  parity test compares them). Every store, web, ingest and nzbd test runs on both backends in CI (SEC-104).
  PostgreSQL: the app role cannot run DDL, change audit rows, delete accounts or lower the retention floors; only the
  one-shot `setup` service holds the owner role.
- **Library identity**: `db_state(backend, instance_id)` plus the restore anchor in `paths.state`; a switched backend or
  a foreign/superseded library is refused (`BACKEND_MISMATCH`, `LIBRARY_MISMATCH`), a rolled-back file is
  `RESTORE_DETECTED`, a restored backup is `RESTORE_PENDING` until `nzbd db restore-finish` (both backends).
- **Tantivy search for both backends** (T113, T123; D35 c): an embedded index on local disk (`search.index_dir`,
  derived data, rebuildable, never backed up), fed by a transactional outbox; prefix matching on the last word, typo
  tolerance only as a zero-hit fallback (`search.fuzzy`), fixed English notices ("search narrowed", "approximate
  matches"; the expanded terms are never shown), "more than n" totals when counting would exceed 150 ms, numbered
  pages capped at 100,000 rows (keyset Next/Previous/Last unlimited), a bounded degraded browse while the index is
  rebuilt. `nzbd search status|verify|rebuild`; hidden categories (instance and per user) are filtered inside the
  index query.
- **Ingest at scale** (T114): parallel prepare (`ingest.workers`, default automatic), one commit-group writer
  (`ingest.group_max_jobs` 256, `ingest.group_window_ms` 50), a byte budget (`ingest.max_inflight_bytes` 256 MiB),
  backpressure (`ingest.queue_cap` 1024), a SQLite writer hold cap so sign-ins never wait behind a bulk ingest
  (`ingest.writer_hold_ms` 50), index lag metrics, a **Search index lag** health line (`search.lag_warn_secs`) and a
  scanner pause at `search.lag_pause_rows`. Crash safety at group boundaries is tested on both backends.
- **`nzbd import <dir>`** (T115, D35 Q11, D37 b): host-only initial load through the same pipeline and limits; copies,
  never moves; no symbolic link followed, regular files only, bounded depth and entries; re-runs import nothing twice
  and never bring back a release deleted from the library (`--include-deleted` to override); refuses a directory that
  overlaps the managed ones (`IMPORT_DIR_OVERLAP`, decided by device and inode), root without `--allow-root`, and on
  SQLite a running `serve` (`SERVE_RUNNING`); audited as `library_import`.
- **Personal preferences** (T120): Account > Preferences for every role, own account only: **Hide XXX for me**
  (filtered in the store and index layer, the instance switch `ui.show_xxx = false` still wins) and **Theme**
  `auto` / `light` / `dark` (server-side `data-theme`, CSP unchanged, AA contrast for both palettes). Audited with key
  names only; at most 6 saves per minute per account.
- **v3 deployment** (T116): the installer asks for the backend; `deploy/compose-example/compose.postgres.yaml` adds a
  digest-pinned PostgreSQL 18 with **no network at all** (`network_mode: none`, Unix socket mounted read-only into
  nzbd), uid 999, read-only, capabilities dropped, limited; `deploy/postgres/` ships `postgresql.conf` (scram, `ssl =
  off`, logging that keeps rows, statements and passwords out of the server log, ~1M sizing), `pg_hba.conf` (superuser
  by peer only, `reject` for every other line) and the init script; one-shot `dbsecrets` (passwords generated once,
  never printed) and `setup` (`db migrate --yes` / `db restore`). New CLI: `nzbd db migrate`, `nzbd db restore`.
  `paths.state` (serve lock, restore anchor) lives on its own `nzbd_state` volume on both backends.
- Release gates per backend: `deploy-check`, `e2e`, `restore-drill` (new: fresh install, encrypted backup, database
  lost, restore per RUNBOOK) and `browser-check` (including the three themes).

### Changed

- **Behaviour: lists follow writes within about 2 seconds** (D35 Q4) instead of in the same transaction; upload and
  bulk-edit result pages say changes appear "within a few seconds".
- **Behaviour: busy database or search** (pool exhausted, statement or search deadline) answers a uniform
  `503 BUSY` with `Retry-After` instead of `500 INTERNAL`.
- **Behaviour: a numbered page beyond `search.max_offset`** answers the uniform `400 BAD_QUERY`; use Next/Last.
- **SQLite always runs with `synchronous = FULL`** (D36 c): a committed ingest is durable before its source file is
  moved. PostgreSQL runs with `synchronous_commit = on`.
- **NZB files live on the filesystem only, on both backends** (D36 a): a full backup is the database backup **plus
  `data/store/`**. Automatic and manual backups: SQLite a stripped `VACUUM INTO` copy, PostgreSQL the nzbd snapshot
  export; both strip sessions and credentials-in-flight and are restore-pending.
- **Audit retention is the database's policy** (floors 90 / 365 days enforced by the database), no longer a config key.
- The production image's runtime stage is `scratch` plus the distroless user database (no CA bundle, no
  `SSL_CERT_FILE`): with `db.backend = "postgres"` nzbd refuses to start while `SSL_CERT_*` or any `PG*` variable is
  set (`DB_ENV_AMBIGUOUS`). trivy finds no OS packages in the app image; the Rust dependencies are covered by
  `cargo audit` / `cargo deny`.
- `ingest.workers` defaults to automatic (cores - 1) instead of 1; `ingest.queue_cap` defaults to 1024 instead of 64.
- The installer never takes image names from the environment and refuses non-`:local` image keys in `.env`
  (review 33 L1, the fix planned for 2.1.1); schema migrations and restores never run under a live `serve`
  (`APP_SESSIONS_ACTIVE`, the installer stops nzbd before `setup`).
- Carried from 2.1.0 unchanged: the registration profile (D32), the existing-reverse-proxy installer and header audit
  (D34), bulk actions (T119).

### Removed

- The upgrade path from 2.x (in-place migration, `nzbd migrate --from-sqlite`, the 2.x audit bootstrap, the upgrade
  drill: `scripts/dev upgrade-drill` now says so) (D37).
- SQLite FTS5 search (replaced by Tantivy), the in-database NZB blob store (`store.backend = "db"`, `store migrate`)
  and the `zstd` dependency.

### Fixed (T118 audit, SECURITY_REVIEW section 39)

- **Every orderly stop of `serve` panicked** (M1): on SIGTERM/SIGINT the scan task's handle was awaited twice
  ("JoinHandle polled after completion", exit 101), skipping the ingest drain, the indexer stop, the final anchor write
  and the database close (no data loss: every step is crash-safe). `serve` now exits 0 and logs `shutdown anchor
  written` and `stopped`; tested on both backends and asserted live by deploy-check.
- **`search.index_dir` and `paths.state` are checked against the data directories** (L1): equal to, inside or containing
  `paths.watch`, `store`, `failed`, `duplicates`, `tmp`, `backups` (or each other) is refused (`INDEX_DIR_LOCATION`,
  `STATE_DIR_LOCATION`), by canonical path and by device/inode. The index garbage collection removes only generation
  directories nzbd created, and `nzbd search status|verify` no longer create or chmod the directory.
- **Root refusal for every state-touching command** (L2): `serve`, `backup`, `health`, `config check`, `search`,
  `failed`, `trash`, `cleanup`, `store`, `keys`, `user`, `apikey`, `metrics` and `db set-retention` now refuse to run
  as root unless `nzbd --allow-root <command>`; detection uses the effective uid (`geteuid`) and can no longer fail open.
- **The `search_query` fuzz target compiles again** (L3) and CI builds every fuzz target per commit.

### Known residual risks (read before an internet-facing or shared install)

From SECURITY_REVIEW section 39.8 (T118 audit; no open Critical or High) and OPERATOR_SECURITY:

1. **SQLite: no protection inside the database against code execution as the service uid.** Such an attacker can
   drop triggers, rewrite or purge the audit history and recompute the unkeyed chain; PostgreSQL limits `serve` to the
   app role. The control on both backends is the off-host copy of the `audit chain anchor` line (RUNBOOK section 9).
2. **The audit chain is unkeyed** (D30 deferred); the anchors live in the container log (json-file 10 MB x 5) unless
   you ship or copy them.
3. **PostgreSQL: a compromised `serve` can change account contents** (roles within the last-admin rule, password
   hashes, TOTP secrets, disabled state) through the app role; it cannot delete accounts, rewrite audit rows or lower
   retention floors.
4. **PostgreSQL superuser = any uid-999 process with the socket volume** (peer authentication; deploy-check pins the
   holders; adding such a container needs Docker daemon access, which is root-equivalent).
5. **No TLS to PostgreSQL** (D35 Q10): socket by default; the IP mode is plaintext on an internal network and not
   templated.
6. **Restore detection residuals:** a joint rollback of the database (or `pg_data`) and `paths.state`; the last
   ~10 s before a snapshot taken without an orderly stop; a PostgreSQL point-in-time restore to fewer than ~32 audit
   rows before the anchor across a purge. A restored backup undoes revocations until `nzbd db restore-finish` (`serve`
   refuses until then, both backends).
7. **Backups:** encryption is optional; a plaintext backup is neither confidential nor authenticated; it holds password
   hashes, sealed TOTP secrets, key hashes and emails. A PostgreSQL restore decrypts to `data/tmp` for the duration of
   the restore.
8. **Emails** are stored in clear (D32); a deleted account's address can survive in free pages and the WAL of raw
   database copies.
9. **Network placement** (D34): on a shared proxy network every neighbour container reaches nzbd's login and upload
   API without the proxy's outer login, and nzbd has a route out (the application opens none). The trusted proxy is a
   single IP: an unpinned proxy address makes the per-IP limits shared and can trust a container that later takes the
   old address. Behind Docker Desktop all LAN clients share one address (and one throttle budget). The proxy password
   is the outer control (Basic auth is not rate-limited).
10. **Accepted authentication trade-offs:** D31/R7 (knowing a login name, an attacker can keep that account's logins
    from unknown addresses throttled); D26 a (anonymous callers can tell "needs a session" from an unknown path); D32
    (a self-chosen display name may hint at the login name).
11. **Derived index data:** terms of deleted releases stay in Tantivy segments until merged; the index directory is
    0700, never backed up, and memory-mapped (a file truncated under the running process, possible only for the
    service uid or root, can kill the process; the next start rebuilds).
12. **Third-party code outside `cargo audit`:** the proxy image (Caddy, Go) is checked by the nightly trivy run and
    the build's Go/x-net version floors only; the app image has no OS packages for trivy to see. Two advisories are
    ignored with fail-closed guards (RUSTSEC-2023-0071, RUSTSEC-2026-0253).
13. **Ingest bounds that depend on the operator:** staged uploads waiting in the queue (up to `ingest.queue_cap` x
    `limits.max_file_bytes` in `tmp/`, bounded by the storage guard and the upload budgets); one maximal NZB can hold
    the SQLite writer beyond `ingest.writer_hold_ms`; `nzbd import` reads whatever the CLI user can read in the source
    tree (hard links accepted, mount points traversed). On PostgreSQL an import next to `serve` can use most of the
    30-connection budget; after a group-wide transient error the job-by-job fallback pays one timeout per job (review
    38 I3, I5).
14. **Performance budgets are unmeasured** (T117 runs only on owner request), including the deadline-bounded exact
    count behind offset pages beyond `search.max_offset`.

Security reviews for this line: `docs/SECURITY_REVIEW.md` sections 30-39. The T118 audit (section 39) found no
Critical or High; its Medium and Low findings are fixed above.

## 2.1.0 (2026-10-15)

Registration profile (T109, D32, migration 0014), a reworked installer (generated `compose.yaml`, host-editable config
file, existing reverse proxy support, header audit; deployment reviews SECURITY_REVIEW sections 26 and 27), owner
decision D34 and bulk actions on releases (T119, section 29). No new crate, no new dependency.

### Upgrade notes: 2.0.0 -> 2.1.0 (read first)

- **Re-run `./install.sh` and keep your `.env`** (RUNBOOK section 5, "Upgrading from 2.0.0"): backup, `git pull` (or
  unzip the new bundle), `./install.sh`, answer `1` (deploy) and keep the existing `.env`. 2.1.0 no longer tracks
  `deploy/compose.yaml`: the installer generates it from `deploy/compose-example/`, removes the `COMPOSE_FILE` line a
  2.0.0 installer wrote into `.env`, and creates `deploy/config/nzbd.toml` once. A plain `docker compose build` with a
  2.0.0 `.env` fails until the installer has run.
- **Migration 0014** (two `ADD COLUMN`s: `user.email`, `invite.name_refusals`; no rewrite, no backfill) runs at the first
  start. It is **forward-only**: a 2.0.0 binary refuses the migrated database. Rollback is the pre-upgrade backup plus
  the previous image (RUNBOOK section 5, "Roll back"); existing accounts keep their display name and have no email.
  Tested on a real, populated multi-user 2.0.0 data directory (`upgrade_2_0_0.rs` and `scripts/dev upgrade-drill`:
  data intact, audit anchor unchanged, sign-in with the stored password and TOTP, a 2.0.0 image refuses the result).
- **Behaviour change: delete forms must send `sha` / `sel`.** `POST /release/{id}/delete` now requires the `sha` field
  (SHA-256 of the release the confirmation page showed) and the new `POST /releases/bulk/delete` the `sel` field
  (digest of the listed selection). The shipped templates send them; a request without the field (or with a stale one)
  is treated as a mismatch and gets the confirmation page again, before the typed word and re-authentication (nothing
  is consumed, nothing is moved). Anything that scripted the 2.0.0 delete form must load the confirmation page first.
  The upload API (`POST /api/v1/nzb`) is unchanged.

### Added

- **Registration profile** (T109, D32, migration 0014, SEC-085): accepting an invitation at `/invite` now also asks for
  an **email** and a **display name**. The invitee chooses the display name (3 to 32 of `A-Z a-z 0-9 _ -`; never a
  login name or a `user-<n>` handle); a name that is not available is refused, and the 3rd refusal cancels the
  invitation. The email is visible only to the account itself (Account page, new **Email** row) and to administrators
  (new **Email** column on the Users page, new `EMAIL` column in `nzbd user list`); it is never logged, never in the
  audit trail, cleared when an account is deleted and never used to send anything (still zero outbound connections).
  Accounts created by `nzbd user create` and existing accounts keep their display name and have no email. Recovery
  codes are redeemed as before (the two new fields are ignored).
- **`nzbd security-headers`**: prints the security response headers nzbd sets on HTML pages (`Name: value` per line),
  from the same list the middleware uses. Needs no config, database or network.
- **`deploy/audit-headers.sh <https-url> [--user NAME]`**: compares what your reverse proxy delivers for `/login` with
  `nzbd security-headers` (OK / CHANGED / MISSING, HSTS OK/WEAK/MISSING with max-age >= 180 days, `Server` and
  `X-Powered-By` as INFO; exit 0/1/2). HTTPS only, no redirect followed, the password is prompted by curl. The installer
  offers it at the end of a deploy with an existing proxy.
- **Generated `compose.yaml`**: the shipped compose files moved to `deploy/compose-example/`; `./install.sh` renders
  them with `.env` and your answers into one self-contained, git-ignored `deploy/compose.yaml` (mode 0600, active
  profiles only). An existing hand-written `compose.yaml` is backed up first.
- **Host-editable config file**: the installer creates `deploy/config/nzbd.toml` once (every setting commented out,
  0644, no secrets, never overwritten); it is mounted read-only at `/etc/nzbd/config.toml` and `nzbd` reads it through
  the new `NZBD_CONFIG_FILE` variable when `--config` is not given, so `serve` and every
  `docker compose exec nzbd /nzbd ...` use the same file.
- **Installer**: a *generate only* run (writes `.env` and `compose.yaml`, validates them with `docker compose config`,
  creates nothing); an **existing reverse proxy** (Traefik, nginx, Caddy ... in Docker) on a shared network with a
  validated static IP for nzbd (needs Docker Compose >= 2.24.4); Traefik labels suggested from the running containers
  and an optional outer basic-auth login.
- `scripts/benchmark.sh`: parameterised benchmark front end with profiles (plan only unless `--run`; T110). No
  benchmark was run for this release.
- **Bulk actions on releases** (T119, the 2.x port of the unmerged 1.x bulk branch; fulfils the optional T073 "bulk
  category edit"). For members and admins the index and search result list has a checkbox per row and an action bar
  below the table: set the category or set/clear the source label of the selection (any release, D26 c), up to 100 per
  request. Admins also get **Delete selected...**, which asks for the typed word, password and authenticator code like the
  single delete, moves every NZB to the trash and reports per release. Viewers see no checkboxes; the routes refuse lower
  roles with the uniform 404. A plain form post that works without JavaScript (a *select all on this page* box appears
  when `app.js` runs). Edits are one transaction that re-validates the actor and writes the single-edit audit row per
  release (old and new value) plus a `bulk_edit_category` / `bulk_edit_source` summary; a bulk delete writes
  `release_delete` per release plus `bulk_delete`. If any id is unknown or hidden the whole request is the uniform 404.
  The delete is bound to the releases the confirmation page listed (a digest of their ids and SHA-256s is posted back
  and compared before re-authentication). Each account may send at most 10 bulk edit requests per minute (`429` with
  `Retry-After` beyond). New routes `POST /releases/bulk` (member), `POST /releases/bulk/delete/confirm` and
  `POST /releases/bulk/delete` (admin). No migration, no new dependency.

### Changed

- **Single delete bound to the confirmed digest** (T119, review M1): the confirmation page posts back the SHA-256 of
  the release it showed (field `sha`) and `POST /release/{id}/delete` moves the release only while it still has that
  digest (release ids are reusable SQLite rowids). A release replaced by a different NZB after the page was opened
  shows the confirmation page again with "This release changed since you opened this page; review it again." before
  the typed word and re-authentication (nothing consumed); the move transaction re-checks the digest, so a replacement
  during the final request answers the uniform 404. A request without the field is treated as a mismatch.
- **Existing reverse proxy on a shared network (D34)**: accepted as an opt-in exception to SEC-041. The installer now
  states both consequences (other containers on the network reach nzbd without the proxy's outer login; nzbd gets a
  route out), asks with default no, applies the check to choice 1 when the typed network already exists, and repeats
  the warning on re-runs. OPERATOR_SECURITY has a new "Existing reverse proxy" section.
- Installer: declining the Traefik outer login is warned (and confirmed, default no); the trusted proxy address must be
  pinned (warnings for an unpinned or blank address and for a mismatch after deploy); the generated Traefik rule is
  ``Host(`site`) && !Path(`/healthz`)``; every value read back from `.env` is validated again (site, names, IPs,
  subnets) before it reaches a label or shell arithmetic; control characters are stripped from other containers'
  labels; the generate-only listing masks bcrypt hashes; the password-hashing container runs without network, read-only,
  unprivileged; a symlinked `config/nzbd.toml` is refused; installer temporaries are git-ignored.
- RUNBOOK section 5: upgrade and rollback re-run `./install.sh` (keep `.env`), with notes for upgrading from 2.0.0
  (`COMPOSE_FILE` cleanup, tracked `compose.yaml`).
- The compose template's images are `${NZBD_IMAGE:-nzbd:local}` / `${NZBD_PROXY_IMAGE:-nzbd-proxy:local}` (the
  rendered `compose.yaml` still says `nzbd:local`). The release gates build per-run `:gate-<pid>` tags and never
  touch the `:local` images an operator on the same host deploys with.

### Fixed

- The installer no longer exits silently when no running Traefik router uses a middleware, or when the hashing
  container fails.
- With a Traefik basic-auth login, `NZBD_PROXY_HASH` in `.env` no longer receives a copy of that hash (it belongs to the
  bundled proxy and stays `unused`).

## 2.0.0 (2026-10-14)

Multi-user release (Phase 10, T100-T106): several accounts with roles on **one shared library**, invite-only, still
zero outbound connections, still one SQLite file. Three forward-only migrations (0011, 0012, 0013), no new crates, no
new network surface except an optional, off-by-default metrics socket. Upgrading from 1.1.0: see "Upgrade notes"
below and RUNBOOK "Upgrading from 1.1.0 to 2.0".

### Added

- **Roles and accounts** (T101, migration 0011): `viewer` (browse, search, download, explore), `member` (plus adding
  NZBs by UI form and API, editing the category and source label of any release, own API keys) and `admin` (plus the
  Users page, every key, operations pages, cleanup and delete). The administrator role can be granted only with `nzbd`
  on the host. A role-denied request is the same 404 as an unknown path. Last-admin protection in the transaction and as a
  database trigger; accounts are tombstoned, never deleted.
- **Invitations and recovery** (`/invite`): single-use codes shown once (only a hash is stored), 48 h default, staged
  credential swap for recovery (nothing changes until the new second factor is confirmed), per-account throttling and
  a lock keyed on (account, client address /64), `nzbd user invite|create|list|set-role|disable|enable|delete|unlock|
  revoke-sessions|set-display-name|enroll-token|reset-password|reset-mfa`.
- **Users page**, attribution on the shared library (**Added by** shows a display handle `user-<id>`, login names are
  admin-only), per-account upload budget.
- **Scoped API keys** (T103, migration 0012): every key belongs to an account (`upload` scope, the only one), per-key
  rate limit (`nzbd apikey create --rate N`, 1-30, can only lower the instance budget), owners revoke their own keys,
  admins revoke any; `revoked_by` recorded.
- **Tamper-evident audit log** (T105, migration 0013, SEC-080..084): every audit row is hash-chained in two classes
  (log, account), `nzbd audit verify` (exit 0 / 2 / 1) and `nzbd audit export [--verify]`, a one-off bootstrap chains the
  rows that exist at upgrade, the content of a row is immutable at the SQL level, anchors (`head_log`,
  `head_account`, `rows`) are logged at startup and after every backup and purge.
- **Metrics listener** (T105): `[metrics] listen` (off by default, loopback unless `allow_back_network`), plain
  `nzbd_*` counters, `nzbd metrics`. Never a route of the app and never proxied (`deploy-check` asserts it).
- **Encrypted backups and key rotation** (T104, SEC-052/053): `maintenance.backup_encryption_key_file` writes
  `nzbd-...Z.sqlite.enc` (XChaCha20-Poly1305, chunked, authenticated), `nzbd backup decrypt`, and
  `nzbd keys rotate-totp --new-key-file F [--dry-run]`.
- **`SearchIndex` trait** (T091/T102): the search engine behind the listing is an abstraction over the unchanged SQLite
  FTS5 index (conformance suite, concurrency tests, stat-tile cache invalidated by a release epoch). No behaviour
  change at the HTTP surface.

### Security and operations (re-audit of Phase 10, T106; fixes T107, T108)

- **`nzbd db restore-finish [--dry-run] [--yes]`** (T107, SEC-068): the mandatory step after **every** restore, run
  on the host before `serve`. A restored backup silently undoes revocations. In one transaction it deletes every
  session, open invitation, MFA recovery code, staged credential, pending MFA enrollment token and throttle/lock row,
  **revokes all API keys**, writes one `cli` audit row and prints every account (role, enabled/disabled), the audit
  anchor and next steps. It does **not** repair what the snapshot held: roles, disabled state and password hashes are
  exactly as of the backup (review them, `user set-role|disable|reset-password|reset-mfa`), keys must be re-created, and
  it cannot know about accounts created after the snapshot. `--dry-run` writes nothing (not even the journal mode);
  idempotent; never reachable over HTTP; `serve` does not refuse a stale database.
- **Staged TOTP secret re-seal** (T107, SEC-053): `nzbd keys rotate-totp` also re-seals the secret parked in a staged
  recovery (`credential_staging`), so the swap still works after a rotation.
- **Key files** (T107, SEC-042): a symlinked key file and an all-zero key are refused, and the base64 error names the
  key; the shipped layout (named volume, secrets file) is unaffected.
- **Audit anchors** (T107, SEC-080): documented that the shipped log rotation is not an anchor archive; ship the
  container log off the host (RUNBOOK section 9).
- **Scene parser** (T108): an inverted episode range such as `S01E05E03-04` overflowed in debug builds (found by the
  fuzz smoke gate); it now yields no range, with a regression test and a hostile seed.
- **Re-audit result** (`docs/SECURITY_REVIEW.md` sections 24 and 25): verdict **ship after fixes**, no Critical or High
  finding; the Medium (restore hygiene) and the Low/Info fixes above are done and re-reviewed.

### Configuration keys (all optional)

`security.multi_user` (default `false`), `security.registration_enabled` (`true`), `security.invite_ttl_hours` (48),
`security.recover_ttl_hours` (2), `security.max_accounts` (100), `server.public_url`, `limits.upload_per_session_per_min`
(now counted per account), `maintenance.account_audit_retention_days` (365), `maintenance.backup_encryption_key_file`,
`metrics.listen`, `metrics.allow_back_network`. Full table: `docs/CONFIGURATION.md`.

### Changed

- `nzbd user create` takes `--role`; a second account needs `security.multi_user = true` (`MULTI_USER_OFF` otherwise).
- `limits.upload_per_session_per_min` counts per account, not per session.
- Audit rows carry `actor_id`, `actor_kind`, `actor_role`, `target_id`; legacy 1.x rows are attributed only by an
  allowlist and otherwise stay "unknown" (better unattributed than misattributed).

### Upgrade notes: 1.1.0 -> 2.0.0

Take a backup and copy it off-host, **stop the old container before the first start of the new version**,
`docker compose build`, `docker compose up -d`, `nzbd health`. The first start applies migrations 0011-0013 behind the
`503 STARTING` page and chains the existing audit rows once (about 20 s per 300,000 rows).

- **Migrations 0011-0013 are forward-only.** A 1.1.0 binary refuses the upgraded database (tested against the real
  1.1.0 production image in `scripts/dev upgrade-drill`). Rollback is the pre-upgrade backup plus the previous image.
- **`security.multi_user` is OFF after the upgrade.** Nothing flips it. The one account becomes the administrator,
  existing API keys become that account's, every release, blob and the trash are unchanged, and the 1.x behaviour is
  what you get until you set `NZBD__security__multi_user=true` and restart.
- The single sign-in lock moved to the per-(account, address) model; `user.failed_logins` / `locked_until` stay unused.
- Backups taken before the upgrade restore into 2.0 and migrate on open; backups taken by 2.0 are refused by 1.1.0.
  Run `nzbd db restore-finish --yes` after every restore (RUNBOOK section 2, step 5).
- Optional: a backup encryption key (RUNBOOK section 2), the metrics listener (section 9).

### Residual risk and open decisions (read before tagging)

- **R7** (SECURITY_REVIEW section 20, accepted N2 residual): knowing only a login name, an attacker can keep that
  account waiting when it signs in from an address outside its last five completed-login addresses. Accepted by the
  owner (D27, D31, 2026-10-14). Mitigation text is in the RUNBOOK.
- **D28 `registration_enabled`**: wording confirmed by the owner 2026-10-14.
- **D29**: admin key revocation without re-authentication, no admin-create-key UI (CLI break-glass); confirmed by the
  owner 2026-10-14.
- **D30 (deferred)**: an optional keyed (HMAC) audit chain is not in 2.0.0. The chain is unkeyed plus logged anchors,
  and SEC-080 and RUNBOOK section 9 say exactly what that does and does not catch.
- L2 of the re-audit (credential-history audit events stay in the 90-day class) is an owner choice, not a defect.
- Tagged `v2.0.0` locally after the full nightly passed; publishing is the owner's step.

## 1.1.0 (2026-10-11)

Large-library release (T087-T090, T092). No new crates, one new optional setting (`[db] startup_check`, default `fast`) and one forward-only migration (0010).
Upgrading from 1.0.0: see "Upgrade notes" below and RUNBOOK section 5.

### Added

- **Keyset (cursor) paging** of the release listing (T089). Previous/Next on the index are cursor links
  (`after=` / `before=`, an opaque hex cursor bound to its sort), so a page costs the same at any depth and stays stable
  while releases are ingested or deleted. Numbered, First and Last links keep using `page=N`. Malformed, foreign-sort
  or doubled cursors answer `400 BAD_QUERY`; hidden (`show_xxx = false`) categories stay hidden. Works without
  JavaScript.
- `nzbd db check [--quick|--full]` (T088, T090): read-only database check on demand (exit 0 ok, 2 damaged, 1 other
  error). It refuses to run as root unless `--allow-root` is given; use
  `docker compose exec nzbd /nzbd db check`.

### Changed

- **Sort and category pages at 1,000,000 releases** (T087, migration 0010 `sort_indexes`): sort orders no longer sort the
  whole library, deep category pages and text + category searches use a deferred-join planner that walks from the nearer
  end. Measured on a 1 M-release corpus: every page under 250 ms p95 warm (before: up to 11 s at deep offsets, past
  the 15 s timeout on the last page); see `docs/BENCHMARK.md`. Ascending sorts break ties by ascending id.
  SQLite `temp_store=MEMORY` on every connection so building the new indexes fits the 16 MiB `/tmp` tmpfs of the
  production container.
- **Fast startup on large libraries** (T088, hardened in T090). `nzbd serve` binds the listener first and answers a static
  `503 STARTING` page (`Retry-After`, security headers, no database access) until the database is open; migration
  progress is logged. The default startup check is now bounded (`[db] startup_check = "fast"`: schema plus the
  small account tables, milliseconds at any size; was `integrity_check` + `foreign_key_check`, 107-130 s cold at
  1,000,000 releases). Pending migrations always run the full check first. `quick` and `full` restore the
  whole-file checks. New `nzbd db check [--quick|--full]` (read-only, exit 0/2/1) runs them on demand and is part of the
  upgrade drill. `nzbd healthcheck` prints `starting:` instead of `unhealthy:` while the database opens (both exit 1).
  No new dependencies.
- Startup hardening (T090): a server error or panic while the database opens makes `serve` exit non-zero, SIGTERM during
  the open stops cleanly before recovery/ingest start, damaged-file errors map to exit 2 and everything else to exit 1,
  and a ledger entry unknown to the binary is rejected before any check or migration.
- Container `HEALTHCHECK --start-period` is 600 s (a first open after upgrade may run the full check and index build).

### Upgrade notes: 1.0.0 -> 1.1.0

Take a backup and copy it off-host, rebuild (`docker compose build`), `docker compose up -d`, then `nzbd health`. The
first start after the upgrade applies migration 0010 behind the `503 STARTING` page and logs its progress; on very large
libraries (hundreds of thousands of releases) allow a few minutes. Migration 0010 is forward-only: a 1.0.0 binary
will not start on an upgraded database, so rollback means the pre-upgrade backup and the previous image. No
configuration change is required; `[db] startup_check` defaults to `fast`.

### Security

- Reviews T088, T089 and T090 (`docs/SECURITY_REVIEW.md` sections 14-16): no Critical, High or Medium findings; the five
  Low findings of the T088 review are closed.

## 1.0.0 (2026-10-10)

The 1.0 milestone (Phase 8, T080-T086). Upgrading from 0.1.0: see "Upgrade notes" below and RUNBOOK section 5.

### Added

- **Database blob store** (T080, migration 0007, supersedes T070): `[store] backend = "fs" | "db"` (default `fs`, no
  behaviour change). `db` keeps NZBs as zstd-compressed rows in the SQLite database, so `nzbd backup` snapshots contain
  the library. Reads fall back to the other backend when the configured one has no valid copy. `nzbd store migrate
  --to db|fs [--dry-run] [--limit N] [--finalize]` is resumable and per-blob SHA-verified; it never deletes
  (`--finalize` moves verified source copies to `store/migrated/` or to the `nzb_blob_trash` table).
  `store verify|gc|gc-restore` and the health deep check work for both backends (`--backend` overrides). New
  dependency: `zstd` (C libzstd via zstd-sys, BSD-3-Clause/MIT). Upgrade notes: see RUNBOOK section 8; existing
  installs keep using files until they opt in.
- **Delete release, trash and Cleanup** (T081, migration 0008). A **Delete release** button on the release page leads to a
  confirmation page; the delete needs the typed word `DELETE`, the current password and a fresh authenticator code
  (wrong attempts feed the login lockout) and is audited. The release moves to `release_trash` and its NZB to
  `store/.trash/`, restorable with `nzbd trash restore <id>` until purged; the same bytes can be uploaded again.
  **Admin > Cleanup** shows counts and sizes of three buckets (Trash, Blocked, Failed) and purges each on an explicit,
  re-authenticated, typed confirmation; only nzbd-written files with matching sidecars are removed, never `watch/`, the
  store or duplicates. CLI twin: `nzbd cleanup status|purge --bucket ... [--yes]`, `nzbd trash list|restore|purge`.
  Nothing is ever deleted automatically.

- `ui.show_xxx` (default `true`, env `NZBD__ui__show_xxx`): when `false`, releases in the `XXX` category and its
  children are not displayed (index, search, totals, tiles, timeline, category selects, sidebar link, direct release
  URLs answer the uniform 404). Ingest is unchanged. Restart required. No migration.

- **Edit source label and category after upload; ingest origin** (T084, migration 0009): the release page has an Edit
  card; the index Source column and the release page show how a release arrived (watch, upload, API). htmx 2.0.11 is
  vendored (hash-pinned test, no eval) as progressive enhancement for paging and the explorer; everything works without
  JavaScript.
- **Real-browser check** (T082): `scripts/dev browser-check` drives Chromium and Firefox through the UI (dev tooling
  only, not in the image).

### Release gates (T086)

- **Upgrade 0.1.0 -> 1.0 is tested against a real 0.1.0 data directory** (`crates/nzbd/tests/fixtures/v0.1.0`, written
  by the released 0.1.0 binary): migrations 0007-0009 apply, origin is backfilled, every release stays searchable and
  byte-identical, `store migrate` fs -> db -> fs with `--finalize` round-trips. Per commit in `scripts/dev ci`
  (`upgrade_0_1_0.rs`), and on the production image under its shipped hardening by `scripts/dev upgrade-drill`
  (nightly).
- **Restore drill** automated for both blob backends: backup, lose the database (and with `db` the whole store),
  restore one file, verify, plus `store gc` not touching blobs the snapshot does not know.
- **Proxy image supply chain** (T085-L2): Caddy is built from the committed module lock `deploy/proxy/go.mod` +
  `go.sum` with `-mod=readonly`; the build fails unless the binary reports Go >= 1.26.9 and `golang.org/x/net` >=
  0.60.0. Static deploy checks assert the builder pin, the lock and the assertion.
- **No trivy ignore file**: `scripts/trivy.ignore` is gone; the nightly fails on any fixable HIGH/CRITICAL in the proxy
  or app image.
- Docs: SEC-022 states 6 distinct characters, which is what the code has enforced since T083 (docs said 5).

### Upgrade notes: 0.1.0 -> 1.0

Follow RUNBOOK section 5 ("Upgrading from 0.1.0 to 1.0"). In short: take a backup and copy it off-host, rebuild
(`docker compose build`; the proxy image is now compiled from source and needs the Go module proxy at build time),
`docker compose up -d`, then `nzbd health` and `nzbd store verify`. Migrations 0007-0009 run automatically and are
forward-only: a 0.1.0 binary will not start on an upgraded database, so rollback means the pre-upgrade backup and the
previous image. `store.backend` stays `fs`; no configuration change is required. The password policy now requires 6
distinct characters; existing passwords keep working.

### Security (T083, residual-risk closure)

- Password policy: at least 6 distinct characters, no repetition/keyboard-walk/sequence patterns, not on an embedded
  common-password list (applies to `user create`, `reset-password` and the account page; existing passwords keep working).
- The login-form token is bound to an HttpOnly cookie nonce and single-use (also after a failed attempt).
- XML prolog: any text, CDATA, reference or processing instruction before the root, and a second/late XML declaration, are rejected.
- Proxy image: Caddy v2.11.7 is compiled with Go 1.26.9 and `golang.org/x/net` 0.60.0; `scripts/trivy.ignore` was emptied (and removed in T086).
- Per-IP upload rate limit counts files (UI) instead of requests.

## 0.1.0 (BETA)

First release. A single-user, security-first NZB indexer: no Usenet access, no outbound network, upload-only API.

### Shipped

- **Parser and analysis** (`nzb-core`): streaming, hardened XML parser (DOCTYPE and entity defence with the single
  owner-approved plain `<!DOCTYPE nzb>` exception, depth/size/count limits, wall-clock deadline), sanitizer for every
  NZB-derived string, subject/filename parsing, file kinds, missing-segment ranges, par2 and obfuscation heuristics,
  Scene release-name parser and a rule-driven categorizer into a Newznab-style taxonomy. Six fuzz targets.
- **Storage** (`nzb-store`): SQLite (WAL) with forward-only migrations, FTS5 search, content-addressed filesystem store
  (tmp + fsync + rename), consistent backups (`VACUUM INTO`, 0600, rotated), `store verify`, quarantining `store gc`
  and `gc-restore`.
- **Ingest** (`nzb-ingest`): watch folder (events plus periodic scan, stability check, symlink/hidden/temp rules),
  one pipeline for watch, UI upload and API upload, duplicates handling, `failed/` with `reason.json`, crash-safe
  order of operations with startup recovery, retention that moves instead of deleting, `failed list|retry`.
- **Web** (`nzb-web`): login with Argon2id + mandatory TOTP, enrollment token, recovery codes, sessions, lockout and
  throttling, CSRF, strict CSP and security headers, index/search/filters, release page and NZB/segment explorer,
  download, category override, upload form, admin page, health dashboard, account page, API keys, upload rate limits
  and a disk-space guard (507).
- **Operations** (`nzbd`): CLI (`serve`, `config check`, `healthcheck`, `health`, `user`, `apikey`, `backup`, `failed`,
  `store`, `categories`, `keygen`), JSON logs with secret scrubbing, graceful shutdown.
- **Deployment**: multi-stage production image (static musl binary, distroless, non-root uid 10001, digest-pinned
  bases, multi-arch via `scripts/dev release-image`), `deploy/compose.yaml` (read-only rootfs, all capabilities
  dropped, no-new-privileges, internal network without egress, nothing published except the proxy), non-root
  zero-capability Caddy with TLS and a Basic-auth gate, key generation service.
- **Quality gates**: `scripts/dev ci` (pin check, SEC-id coverage, fmt, clippy `-D warnings`, tests, offline tests,
  cargo-deny and cargo-audit with warnings fatal, static deploy checks); nightly fuzz, `deploy-check` (container
  hardening and no-egress proof) and `e2e` (whole journey through the proxy).
- **Security audit** (T061): zero Critical and zero High findings open. Medium and Low findings are tracked in
  `docs/SECURITY_REVIEW.md`; the fixes are in this release (see "Audit status" below).
- **Documentation**: `docs/INSTALL.md` (deploy from scratch), `docs/CONFIGURATION.md`, `docs/RUNBOOK.md` (day-2
  operations), specs and the security review.

### Known limitations (BETA)

- No segment availability check: segment counts are displayed as `N/N` (`SEGMENT_HEALTH_CHECK_AVAILABLE = false`).
- No release deletion and no DB-blob store yet (T070, T071). NZBs are never deleted automatically.
- `nzbd ingest <file>` is not implemented (use the watch folder, UI or API).
- Audit status (`docs/SECURITY_REVIEW.md` section 10), final audit: 0 Critical, 0 High open.
  - Fixed: M-1 (proxy log filter redacts `X-Api-Key`, `X-Csrf-Token`, `Cookie`, `Authorization`, `api_key`/`key` query
    parameters), M-3 (`panic = "abort"` removed from the release profile; release-profile isolation test in the
    nightly), L-1 (json-file log rotation 10m x 5), L-2 (database, `-wal`, `-shm` and sidecars 0600), L-3 (in-process
    backup and purge scheduler, `[maintenance]` section, default daily, 14 kept, 90 days of logs), L-5 (store reads
    capped at 2x `max_file_bytes`), L-14 (`stop_grace_period: 30s`), L-15 (dev build jobs default 2), and the Info fixes
    I-1, I-8 and I-9 (the other Info items are notes, not defects).
  - Mitigated, residual until upstream fixes it: M-2 (pinned Caddy v2.11.7 built with Go 1.26.8 has three fixable HIGH
    CVEs; no fixed image exists yet). Mandatory nightly trivy scan with a dated ignore list
    (`scripts/trivy.ignore`, entries expire 2026-11-30); see RUNBOOK section 5 and DEPLOYMENT "Known residual risks".
  - Accepted, unchanged: L-4 (segment display switch is off by owner decision), L-6 (`db.durable = false` default, last
    commit can be lost on power failure, recoverable by re-dropping the file), L-7 (guard that `dev-tools` cannot reach
    a release is a grep), L-8 (workflows pin actions by tag; trivy part is addressed by M-2), L-9 (hyper at the app accepts
    odd framing, reachable only bypassing Caddy), L-10 (Docker Desktop shares per-IP buckets between LAN clients),
    L-11 (weak-but-long passwords such as 12 spaces pass the policy), L-12 (stateless pre-session login token valid
    10 minutes), L-13 (failed-file sidecar read follows a swapped symlink, operator-level).
- The proxy password is not rate-limited; per-IP throttles are shared by all LAN clients on Docker Desktop.
- Browsers without `Sec-Fetch-Site` (Safari before 16.4) cannot log in, by design.
