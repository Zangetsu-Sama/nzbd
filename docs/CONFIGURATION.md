# Configuration reference

Every setting, with defaults. Environment variables override the file (`NZBD__section__key`).

Configuration is built-in defaults, optionally a TOML file (`nzbd serve --config FILE`), then environment overrides in the
form `NZBD__<section>__<key>=<TOML value>`, for example `NZBD__ingest__failed_retention_days=30` or
`NZBD__server__allowed_hosts='["nzbd.lan"]'`. Unknown keys are rejected at startup.

**In the compose stack, edit `deploy/config/nzbd.toml` on the host.** `install.sh` creates it once (every setting
commented out) and never overwrites it; the stack mounts it read-only at `/etc/nzbd/config.toml` and sets
`NZBD_CONFIG_FILE` to that path, so `serve` and every `docker compose exec nzbd /nzbd ...` command read the same file
(without `--config`, nzbd uses the file named by `NZBD_CONFIG_FILE` when it is set). Apply a change with
`docker compose restart nzbd`. It holds no secrets (mode 0644 so the container user can read it). The installer sets
`server.listen`, `server.trusted_proxies` and `server.allowed_hosts` as env vars, which override the file: change those
by re-running `./install.sh`. Alternatively, env overrides go in `deploy/compose.override.yaml` (never edit the generated
`deploy/compose.yaml`):

```yaml
services:
  nzbd:
    environment:
      NZBD__ingest__failed_retention_days: "30"
```

Validate any change with `docker compose exec nzbd /nzbd config check` (after restarting: env changes need
`docker compose up -d`). Secrets are never configured in values, only as a key file path.

| Key (env `NZBD__section__key`) | Default | Meaning |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` (image/compose: `0.0.0.0:8080`) | Listen address. Inside the internal network only. |
| `server.trusted_proxies` | `[]` (compose: the proxy IP) | IPs whose `X-Forwarded-For/Proto` are honored. Single IPs, no CIDR. Warning when `listen` is not loopback and this is empty. |
| `server.allowed_hosts` | `[]` (compose: `NZBD_SITE`) | Extra accepted `Host` names (lowercase, no port). `localhost` and IP literals are always accepted; anything else gets `400 BAD_HOST`. |
| `server.insecure_cookies` | `false` | Plain-HTTP cookies. Development only (logged as a warning). |
| `server.public_url` | `""` (unset) | the address the invite and recovery page prints, for example `https://nzbd.example.lan`: `https` (or `http` only with `insecure_cookies`), host and optional port, no path, query or userinfo; anything else fails startup. Unset = `https://<first allowed_hosts entry>`, else no address is printed. The request `Host` header is never used. |
| `paths.watch` | `/data/watch` | Input folder. |
| `paths.store` | `/data/store` | Content-addressed NZB store. |
| `paths.failed` | `/data/failed` | Rejected files plus `.reason.json` sidecars. |
| `paths.duplicates` | `/data/duplicates` | Where duplicate copies are moved. |
| `paths.tmp` | `/data/tmp` | Upload staging. Must not equal or nest with the other directories. |
| `paths.db` | `/data/nzbd.sqlite` | SQLite database (backend `sqlite`). Must not lie inside `paths.watch`, `paths.tmp`, `paths.backups` or the index directory (`DB_PATH_LOCATION`, SEC-102). A database from an earlier private version is refused with `LEGACY_DATABASE` and never modified. |
| (compose) `NZBD_NAME_PREFIX` in `deploy/.env` | `nzbd` | Not an app setting: the prefix of the PostgreSQL socket volume and the long-running containers (`<prefix>`, `<prefix>-proxy`, `<prefix>-db`). See INSTALL.md section 10. |
| `paths.state` | `state/` next to `paths.db` (compose: `/state`, its own bind-mounted folder `storage/state`) | `serve.lock` (one `serve` per library) and the restore anchor `db-anchor.json` (0600). 0700. Keep it on its own folder or volume so a snapshot of the data directory cannot roll it back with the database (review 34 M3; health WARN `ANCHOR_SAME_FILESYSTEM`). Env: `NZBD__paths__state`. |
| `paths.backups` | `/data/backups` | Backup output of the scheduler and of `nzbd backup` (`maintenance.keep_backups` kept). |
| `ingest.scan_interval_secs` | `5` | Full scan interval (events are only a hint). `/healthz` is unhealthy when the scan heartbeat is older than 3x this. |
| `ingest.stable_secs` | `5` | Size and mtime must be unchanged this long before ingest. |
| `ingest.workers` | `0` (automatic) | Parallel ingest workers that read, hash, parse and store NZBs (0 = available cores - 1, at least 1; or 1-32). |
| `ingest.queue_cap` | `1024` | NZBs that may wait in the ingest queue (1-8192). The scanner offers at most the free slots per cycle; uploads beyond it get `503 QUEUE_FULL`. Staged uploads waiting in it sit in `paths.tmp` (up to `queue_cap` x `limits.max_file_bytes` in theory; in practice bounded by the upload storage guard, the upload slots and the per-key and per-account rate limits). |
| `ingest.max_inflight_bytes` | `268435456` (256 MiB) | NZB bytes held by the pipeline at once (read, parsed, waiting for the database), whatever the queue length: the ingest memory bound (1 MiB-16 GiB). A file larger than the budget takes all of it and runs alone. |
| `ingest.group_max_jobs` / `ingest.group_window_ms` | `256` / `50` | Commit groups (T114): up to this many NZBs are written in one database transaction; a group waits at most the window for more while workers are still busy. The NZB file is durable before its group commits and the watch file is removed only after it. |
| `ingest.writer_hold_ms` | `50` | SQLite: the longest one commit group holds the single writer; the rest of the group is committed in the next one, so logins and account changes never wait behind a bulk ingest (1-1000). PostgreSQL ignores it. |
| `ingest.duplicates_action` | `"move"` | `move` or `delete` (delete removes only the duplicate copy once the identical NZB is confirmed in the store; logs a warning). |
| `ingest.failed_retention_days` | `0` | Days before failed files are moved to `failed/expired/` (0 = never). Never deletes. |
| `ingest.atomic_moves` | `true` | Require watch, store and failed on one filesystem (atomic renames). |
| `ingest.recursive` | `false` | Descend into watch sub-folders (depth up to 4, symlinks never followed). |
| `ingest.category_from_subfolder` | `false` | A first-level sub-folder named exactly like a category slug provides the category. Needs `recursive = true`. A watch rule with a `category` beats it. |
| `[[ingest.rules]]` | none | Watch-folder rules, see below. At most 64, evaluated in file order, first match wins. Not settable through `NZBD__` env overrides (arrays of tables). |
| `ingest.failed_uploads_max_files` | `1000` | Rotation bound for rejected *uploads* in `failed/` (oldest first, 0 = unlimited). Watch files are never rotated. |
| `ingest.failed_uploads_max_bytes` | `1073741824` | Same, in bytes. |
| `limits.max_file_bytes` | `67108864` (64 MiB, ceiling) | Maximum NZB size. May only be lowered. Keep the proxy body limits above the app ceilings: 65 MiB on `/api/v1/nzb` (one file) and 321 MiB on `/upload` (a batch of up to five maximum-size files plus multipart overhead). |
| `limits.parse_deadline_secs` | `20` (ceiling) | Parse wall-clock budget per file. May only be lowered. |
| `limits.upload_per_key_per_min` | `30` (ceiling) | Uploads per minute per API key (1-30). A key can carry its own lower budget (Account page field or `nzbd apikey create --rate N`); the lower of the two applies. Every upload through a key also spends the owner's API budget, which takes its size from `limits.upload_per_session_per_min` (shared by all of that account's keys, separate from its UI form budget; the table is bounded and fails closed like the others). |
| `limits.upload_per_session_per_min` | `30` (ceiling) | Uploaded files per minute per UI **account** (1-30; several sessions of one account share it). |
| `limits.upload_min_free_bytes` | `1073741824` | Uploads get `507` below max(this, percent) free on `tmp` or `store`. |
| `limits.upload_min_free_percent` | `5` | See above (0-50). |
| `security.totp_key_file` | `/run/secrets/nzbd_totp_key` | File with the base64 32-byte TOTP encryption key; must be mode 0400 and owned by the service user, or startup fails. |
| `security.session_idle_mins` | `30` | Sliding idle timeout. |
| `security.session_max_hours` | `12` | Absolute session lifetime. |
| `security.multi_user` | `false` | explicit opt-in for several accounts. `false` = `/invite` and every `/admin/users*` and `/admin/invites*` route answer 404, `nzbd user create` for a second account and `nzbd user invite` refuse, open invites are revoked at startup. Restart required; no automatic flip. Env: `NZBD__security__multi_user`. |
| `security.registration_enabled` | `true` | only meaningful with `multi_user = true`. `false` removes the invitation surface: no invitation can be created (`/admin/users/invite` and `nzbd user invite` refuse), `/invite` accepts recovery codes only, open invitations are revoked at startup. Accounts then come from `nzbd user create`; admin-issued recovery codes keep working. Restart required. Env: `NZBD__security__registration_enabled`. |
| `security.invite_path` | `"/invite"` (installer: a random `"/join-..."` on a fresh install) | T135: path of the anonymous invitation page (only served with `multi_user = true`), e.g. `"/join-7f3k9q"`. `/` plus one segment of 6-64 characters from `A-Z a-z 0-9 _ -`; it must not equal, start with or be a prefix of the first segment of any built-in route (`/login`, `/logout`, `/static`, `/api`, `/admin`, `/account`, `/release(s)`, `/search`, `/stats`, `/upload`, `/healthz`, `/mfa`, `/`; checked against the route inventory, case-insensitively), else startup and `config check` refuse with `INVITE_PATH_INVALID`. A custom value must not start with `invite` (case-insensitive; only `/invite` itself may). With a custom value `/invite` is the uniform 404. The login page never links to the invitation page (any configuration). Warnings (not refusals): `INVITE_PATH_DEFAULT` while `multi_user = true` keeps `/invite`, `INVITE_PATH_SHORT` for a custom path under 10 characters. The path is printed by `nzbd config check`, `nzbd user invite` and the admin invitation/recovery result pages (with `server.public_url` or the first `allowed_hosts` entry as the full URL), never on an anonymous page. Obscurity only: not a secret, the one-time code is the protection. Restart required. Env: `NZBD__security__invite_path`. |
| `security.invite_ttl_hours` | `48` | lifetime of an invitation code (1-168; the database also caps it at 7 days). Invitations are for `uploader` and `viewer` only. |
| `security.recover_ttl_hours` | `2` | lifetime of an admin-issued recovery code (1-24; the database caps it at 24 h). |
| `security.max_accounts` | `100` | live (non-tombstoned) accounts; 100 is the bound (Users page and Argon2 capacity planning). |
| `db.backend` | `"sqlite"` (compose: from the installer's `NZBD_DB_BACKEND`) | `"sqlite"` or `"postgres"`, a closed set (`"pg"`, `"postgresql"` are refused). Chosen once per library; a switched value is refused at startup (`BACKEND_MISMATCH`, `LIBRARY_MISMATCH`). Env: `NZBD__db__backend`. |
| `db.host` | unset (compose: `/run/postgresql`) | PostgreSQL only: the socket **directory** (absolute path) or an IP literal that is loopback, RFC 1918, RFC 6598 or a ULA (`DB_HOST_NOT_INTERNAL`); never a host name (no DNS). The shipped stack uses the socket only. |
| `db.port` | `5432` | PostgreSQL port (also the socket's port number). |
| `db.name` / `db.user` | `"nzbd"` / `"nzbd_app"` | PostgreSQL database and app role (`^[a-z_][a-z0-9_]{0,62}$`). The app role cannot run DDL, change audit rows or delete accounts; the owner role is never configured here (it lives only in the one-shot `setup` service). |
| `db.password_file` | unset (compose: `/run/secrets/nzbd_db_password`) | PostgreSQL: file with the app role's password (0400, owned by the service user, no symlink, at most 1 KiB, SEC-042 rules). The password is never in the config, the environment, a URL or a log. |
| `db.pool_web` / `db.pool_ingest` / `db.pool_background` | `16` / `4` / `4` (compose: `8` / `2` / `2`) | PostgreSQL connection pools (hard ranges 1-64 / 2-16 / 2-8). Keep their sum plus a few below the server's `max_connections` (30 in the shipped `postgresql.conf`). |
| `db.acquire_timeout_ms` / `db.statement_timeout_ms` | `3000` / `5000` | PostgreSQL: wait for a pooled connection, and the web pool's statement timeout; past either the request gets the uniform `503 BUSY`. |
| `db.startup_check` | `"fast"` | Database check run before serving: `"fast"` (schema plus the small account/config tables; milliseconds at any library size), `"quick"` (`PRAGMA quick_check` over the whole file) or `"full"` (`integrity_check` + `foreign_key_check`, 107 s cold at 1,000,000 releases). Pending migrations always force `"full"` first. The strong checks are on demand: `nzbd db check --full`. Env: `NZBD__db__startup_check`. |
| `maintenance.backup_interval_hours` | `24` | Hours between the in-process backup and purge runs (0-8784). First run 60 s after start. `0` disables the whole job (then schedule `nzbd backup` yourself). Env: `NZBD__maintenance__backup_interval_hours`. |
| `metrics.listen` | unset (off) | address of the internal-only plaintext metrics listener, for example `127.0.0.1:9100`. A second socket, never a route of the app; must differ from the `server.listen` port. Read it with `nzbd metrics`. Env: `NZBD__metrics__listen`. |
| `metrics.allow_back_network` | `false` | required when `metrics.listen` is not loopback (a scraper on the container's internal network). Confirms the port is never published or proxied; startup logs a warning. Env: `NZBD__metrics__allow_back_network`. |
| `maintenance.keep_backups` | `14` | Backups kept by rotation (1-3650). Env: `NZBD__maintenance__keep_backups`. |
| `maintenance.backup_encryption_key_file` | unset (recommended) | File with a base64 32-byte key (`nzbd keygen --out FILE`) that encrypts every snapshot at rest (`nzbd-...Z.sqlite.enc` / `nzbd-...Z.nzbdpg.enc`, SEC-052; `nzbd db restore` then refuses a plaintext file without `--allow-unencrypted`). Same rules as `security.totp_key_file` (regular file, mode 0400, owned by the service user); it must be a different key and live outside `paths.backups` and `paths.tmp`, or startup fails. Unset = plain snapshots. Env: `NZBD__maintenance__backup_encryption_key_file`. |
| `store.backend` | `"fs"` | NZB files live on the filesystem only (D36 a, D37); `"db"` is refused with `STORE_DB_BACKEND_REMOVED`. |
| `search.index_dir` | `index/` next to `paths.db` | the Tantivy search index of both backends (derived data, rebuilt from the database; never backed up). 0700; must not be, contain or lie inside `paths.watch`, `store`, `failed`, `duplicates`, `tmp`, `backups` or `paths.state` (refused with `INDEX_DIR_LOCATION`; `paths.state` likewise with `STATE_DIR_LOCATION`). Only generation directories nzbd created (marker `NZBD_GENERATION`) are ever removed. |
| `search.max_concurrent_searches` | `8` | Searches running at once (1-64); more wait up to 1 s, then the uniform `503 BUSY`. |
| `search.query_deadline_ms` | `2000` | Deadline of one search (1-10000 ms); past it `503`. |
| `search.count_budget_ms` | `150` | Time spent counting; beyond it lists say "more than n" (owner Q1). |
| `search.max_offset` | `100000` | Numbered pages stop at this offset; Next/Previous (keyset) links are unbounded (owner Q2). |
| `search.fuzzy` | `"fallback"` | Typo tolerance: `"off"`, `"fallback"` (only when the exact query finds nothing) or `"toggle"` (a form checkbox). |
| `search.prefix` | `true` | Prefix matching of the last word (bounded by internal expansion budgets). |
| `search.lag_pause_rows` | `1000000` | The watch-folder scanner stops offering files while more than this many changes wait for the search indexer and resumes below half of it (files wait in `watch/`; uploads are not paused). `0` never pauses. Metrics `nzbd_index_outbox_depth`, `nzbd_ingest_paused_for_index_lag`. |
| `search.lag_warn_secs` | `60` | Health shows the **Search index lag** line as WARN when the oldest change not yet in the index is older than this (metric `nzbd_index_lag_seconds`). |
| `search.commit_interval_ms` / `commit_max_docs` / `writer_heap_mib` / `writer_threads` / `rebuild_heap_mib` | `1000` / `10000` / `256` / `2` / `2048` | Indexer tuning: a change is visible in lists within about `commit_interval_ms` (owner Q4: ~2 s); the rebuild heap counts against the container memory limit. |
| `ui.show_xxx` | `true` | `false` hides the `XXX` category and its children everywhere they are displayed (index, search, stat tiles, timeline, selects, release/download URLs answer 404); watch-folder ingest and the upload API are unchanged (an API `X-Category` / `category` hint may name a hidden category) and the files stay in the store; the UI upload form refuses a hidden category as its hint with `INVALID_CATEGORY`, like an unknown one (T143), and uploads without a hint still succeed. With category exclusions, the timeline also omits digest-bearing history whose category can no longer be resolved after trash purge; failures without a release identity remain visible. Operator views (`/admin`, `/admin/health`, CLI) stay unfiltered. Restart required. Env: `NZBD__ui__show_xxx`. |

## Watch-folder rules (`[[ingest.rules]]`)

Each rule has **exactly one matcher** and **at least one action**:

| Key | Kind | Meaning |
|---|---|---|
| `subfolder` | matcher | Name of the file's **first-level** sub-folder of `paths.watch`, compared exactly (case-sensitive) as a string; never joined into a path. The comparison is byte for byte, Unicode normalization included: a folder created as NFD (`Cafe` + combining accent, as some macOS tools do) does not match `"Café"` typed as NFC; check with `nzbd watch rules`. Refused (`RULE_BAD_SUBFOLDER`) if empty, longer than 255 bytes, containing `/`, `\`, `..` or NUL, starting with a dot, not clean text (control or invisible characters, edge spaces), or when `ingest.recursive = false`. |
| `filename` | matcher | Regular expression (Rust `regex` syntax, no look-around or back-references, linear-time matching) over the **sanitized** file name (the one shown as the release's file name, `.nzb` included; bidi, zero-width and control characters already removed). Unanchored: use `^`/`$`, `(?i)` for case-insensitive. 1-512 bytes, compiled once with a 256 KiB program limit and nesting depth 32 (`RULE_BAD_REGEX`). Unicode classes such as `\w`, `\d` or `\p{L}` are large (`\w{30}` already exceeds the limit): use `(?-u)` or explicit ASCII classes like `[A-Za-z0-9_]` for long repetitions; the refusal message says so. |
| `category` | action | A taxonomy slug exactly as `nzbd categories` prints it (`RULE_UNKNOWN_CATEGORY` otherwise; ids are refused). Used as the category **hint**: `category_source = upload`, Scene detection still wins (like `X-Category`). Beats `ingest.category_from_subfolder`. |
| `source_label` | action | Free text written as the release's source label when the release is **created** (a duplicate never relabels). Sanitized like an upload label (64 bytes); empty after sanitizing counts as no action. |

Other refusals: no matcher `RULE_NO_MATCHER`, both matchers `RULE_TWO_MATCHERS`, no action `RULE_NO_ACTION`, more than
64 rules `RULE_TOO_MANY`; unknown keys are a config parse error. `nzbd serve` and `nzbd config check` refuse to start
with the first invalid rule (numbered from 1 in file order).

Rules apply to **watch-folder files only** (not to UI/API uploads, not to `nzbd import`). The first matching rule wins;
a matching rule without `category` leaves the `category_from_subfolder` hint (if any) in place. The rule number is
written to the ingest log (`detail` `rule=N`, also on duplicate rows) and logged as `watch rule matched rule=N`.
Preview with `nzbd watch rules` (read-only dry run, run as the service user; RUNBOOK). Example:

```toml
[ingest]
recursive = true
category_from_subfolder = true

[[ingest.rules]]                 # rule 1
subfolder = "From Seedbox"
source_label = "seedbox"         # label only; files here never reach rule 2 (first match wins)

[[ingest.rules]]                 # rule 2
filename = '(?i)\.s\d{2}e\d{2}\.'  # TOML literal string: no double escaping
category = "tv.hd"
source_label = "tv"

[[ingest.rules]]                 # rule 3
subfolder = "cartoons"
category = "anime"
```

Fixed hard limits (parser, not configurable above the ceilings): 10 000 files per NZB, 100 000 segments per file,
2 000 000 segments total, XML depth 8, subject 2 KiB. Request bodies are 64 KiB except uploads.
`nzbd serve` runs a built-in maintenance task (`[maintenance]` above): a consistent database backup with keep-N
rotation, then purges of expired sessions, log rows past the database's retention policy (audit 90 days, account audit
365 days, ingest log 90 days; the database refuses periods below the floors 90 / 365 days, D35 d; there is no config
keys for them) and API keys revoked more than 90 days ago. Backups land in
`paths.backups` on the same disk, so still copy them off-host (RUNBOOK section 2). Container logs are rotated by Docker
(`json-file`, 10 MB x 5 files per service) and `nzbd` gets a 30 s `stop_grace_period` so a scan cycle can finish on stop.
