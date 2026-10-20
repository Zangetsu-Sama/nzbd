# Security notes for the operator

What protects your instance and what you must keep safe.

- **LAN only.** Do not expose the proxy to the internet. Keep `NZBD_BIND` on the LAN address or loopback, firewall
  everything but the HTTPS port, and treat the proxy password as the outer gate (long and random).
- **Two gates.** The proxy's Basic auth covers every path including `/api/v1/nzb`; the app then requires login + TOTP.
  API clients send both `-u proxyuser:pw` and `X-Api-Key`. The app never reads the `Authorization` header. With your
  own reverse proxy the first gate is yours, and it only covers traffic that goes through the proxy: see
  [Existing reverse proxy](#existing-reverse-proxy).
- **TLS** comes from Caddy's internal CA; HSTS is sent. Cookies are `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`.
  Browsers must send `Sec-Fetch-Site` (all current browsers; Safari 16.4+).
- **Secrets.** The TOTP key exists only in the `secrets` folder of the volumes directory (`NZBD_VOLUMES_DIR`, a plain host folder, mode 0700, owned by the container user): not in `data/`, not in `nzbd backup`
  output, not in git. With PostgreSQL the role passwords are generated files too (never shown, never in the config,
  the environment or a log): the app role's next to the TOTP key, the owner role's only in the `setup_secrets` folder,
  which only the one-shot `setup` service mounts (`serve` refuses to start if it can read it). Passwords, API keys and session ids are stored only as hashes (the TOTP secret is encrypted).
  `deploy/.env` holds the proxy hash: keep it mode 0600; it is git-ignored. `deploy/config/nzbd.toml` holds no secret
  but is a control surface at the same trust level (`server.insecure_cookies`, `metrics.listen`, paths): keep `deploy/`
  writable only by the operator. The installer refuses a symlinked settings file.
- **Container user.** nzbd runs as the numeric `NZBD_UID:NZBD_GID` from `.env` (the installer proposes your own).
  Refused: 0 for either (root; the installer, the `volperms` helper and nzbd itself, which also refuses group 0),
  999 (PostgreSQL's own user: `pg_hba.conf` lets it in as the database **superuser** by peer authentication on the
  socket nzbd mounts), 65532 (the proxy) and 65534 (nobody). The host account with that UID owns the data directory:
  it can read and change every NZB, the SQLite database (password hashes, the sealed TOTP secrets, email addresses)
  and the backups, so it is equivalent to a compromised nzbd for the library. **Use a dedicated account** that no
  other container or login uses: media containers (SABnzbd, Sonarr, Radarr ...) commonly run as `PUID=1000
  PGID=1000`, and sharing those ids hands them nzbd's database. nzbd makes itself non-dumpable at start (review 44
  M1), so that account cannot read the TOTP key, the database passwords, the environment or the memory of a running
  nzbd through `/proc/<pid>/root`, `/proc/<pid>/environ` or `/proc/<pid>/mem` (deploy-check proves it); the key folder
  itself is a host folder owned by that same account, so **the account (and root) can read the key directly**: another
  reason for a dedicated account, and for the image's own `10001:10001`, which no host account has. Members of the `docker` group are root-equivalent anyway.
  Optionally mount the host's `/proc` with `hidepid=2`. The image's own `10001:10001` (proposed when the installer
  runs as root or with rootless Docker / userns-remap) belongs to no host account, so only root touches the data.
- **What is logged.** One JSON line per event on stdout (`docker compose logs nzbd`), no cookies, API keys, passwords,
  TOTP codes or CSRF tokens, no query strings on auth routes. The audit log (login, MFA, key and category changes,
  downloads, uploads, failures) is in the database and visible on `/admin`. The proxy log filter also redacts
  `X-Api-Key`, `X-Csrf-Token`, `Cookie`, `Authorization`, `Referer` and the whole request URI, including its path
  and query string, so error lines (for example the 502 of a cut-off oversize upload) carry `REDACTED` instead.
  With an existing reverse proxy, configure its access and error logs to redact these fields too: the app cannot
  remove a secret from a request that the proxy has already logged.
- **Backups contain** the password hash, the sealed TOTP secret and key hashes: set a backup encryption key
  (RUNBOOK section 2), or encrypt them before copying off-host. Both backends strip sessions, staged credentials, open
  invitations, recovery codes and throttle rows from every backup, and mark it restore-pending.
  With several accounts they also contain each invited account's **email address** (personal data, D32): it is stored in
  clear in the database (`account.email`) and therefore in every backup, visible to administrators and in `nzbd user list`,
  never logged, cleared when an account is deleted (older backups keep it until they are rotated away). nzbd never sends
  anything to it. Clearing is a plain `UPDATE`, so a deleted account's old address can also survive in free pages and
  in the WAL until they are reused or checkpointed: a raw copy of `nzbd.sqlite`/`-wal` (or of the PostgreSQL `pg_data` folder)
  may still contain it (an `nzbd backup` is rewritten and vacuumed, so it drops free pages; restoring an older backup
  brings the address back). Treat raw database copies like backups.
- **Invitation path (T135).** `security.invite_path` moves the anonymous invitation page away from `/invite` (the
  installer writes a random `/join-...` path on a fresh install). That is obscurity only: it keeps automated scanners
  and casual probing off the page, nothing more. The path is not a secret (it is in the settings file, `config check`
  output and the admin result pages, and may appear in access logs like any path); the single-use, 160-bit invitation
  code remains the protection, together with the login rate class, the page's own Argon2 queue and the proxy's Basic
  auth, which you should keep in front of it (do not exempt the invitation path from the proxy login). If you ship
  proxy or access logs to a third party (log service, SIEM, hosting provider), the path travels with them: treat it as
  known to them and change it (restart) if that matters.
- **Lockout.** 5 failed logins **from one client address (/64)** lock the account for that address only: 1 minute,
  doubling to a 1 hour cap (5 minutes for an administrator); a completed login resets it, and so do `nzbd user unlock`
  and `nzbd user reset-password`. 20 failures in an hour from any addresses also limit the account to one attempt a
  minute from addresses that never completed a login (known addresses are unaffected; health WARN, audit
  `account_throttled`). On Docker Desktop, or behind a proxy whose address is not in `server.trusted_proxies`, all
  clients share one address, so the lock and the per-IP budget become shared too: a LAN neighbour who passes the proxy
  login can lock the owner out from that address (documented limitation).
- **Residual risks** of 3.0 (project security review, section 39.8; also the CHANGELOG): proxy
  password strength is the outer control, the per-IP throttles are shared behind Docker Desktop, with SQLite a
  compromised nzbd process can rewrite the audit history ([Choosing a backend](#choosing-a-backend)), the audit chain is
  unkeyed (keep the anchor lines off-host), plaintext backups are neither confidential nor authenticated.

## Choosing a backend

The installer asks once: SQLite (default) or PostgreSQL. Both serve the same features with the same access rules, the
same tamper-evident audit chain and the same restore controls; what differs is **who the database itself can stop**.

| | SQLite | PostgreSQL |
|---|---|---|
| A bug or a careless tool | Triggers and CHECKs refuse: audit rows cannot be edited or purged before the retention floors (90 / 365 days), accounts are never deleted, the last admin stays. | The same rules, plus grants. |
| **A compromised nzbd process** (code execution as its container user, `NZBD_UID`) | **No protection inside the database.** SQLite has no users: whoever can write the file can drop the triggers, **rewrite or delete audit history** (and recompute the unkeyed chain so `audit verify` still says OK), purge before the floors, change `retention_policy`, delete accounts. | `serve` holds only the app role: it **cannot** run DDL, update or delete audit rows, delete account rows or lower the retention floors; those need the owner role, which only the one-shot `setup` service has (review 30 M4), or the superuser, reachable by peer authentication only from processes running as uid 999 with the socket volume mounted (the `postgres` container as shipped). It **can** still change account contents (roles within the last-admin rule, password hashes, TOTP secrets, disabled state: the app role needs `UPDATE` on accounts), i.e. take over accounts; those changes are themselves recorded in the audit history it cannot rewrite. |
| Database network surface | None (a file). | None: the server has no network at all (socket only, mounted read-only into nzbd); superuser by peer only; scram for the two roles. |
| Restore detection | Every nzbd backup is restore-pending; the anchor in `paths.state` refuses a file rolled back by hand (`RESTORE_DETECTED`). **Residual:** a snapshot that rolls back the data directory **and** the `state` folder together is not detected (that is why the state has its own volume; health warns `ANCHOR_SAME_FILESYSTEM` if you put it next to the database). | The same, with the cluster identity in the anchor. Residual: a joint rollback of `pg_data` **and** `state`, the last ~10 s, a point-in-time restore to just before the anchor across a purge. |
| What you operate | One container. | Two more containers (one long-running), a second volume to watch for disk, PostgreSQL major upgrades by export/restore (RUNBOOK). |

**Recommendation.** For a personal library on your LAN, SQLite is fine: an attacker who can execute code in nzbd
already reads everything it can read. For a **shared install** (several accounts, other people's activity in the audit
log) or an **internet-facing** one, choose **PostgreSQL**: the audit history up to the compromise, the retention floors and the
account rows (never deleted) then survive a compromise of the application; account contents can still be changed
through the app role, so after an incident review the accounts (`nzbd user list`) and the audit history. For **both**, the external control for the history is the `audit chain anchor` line that
`nzbd backup` prints and the server logs: copy it off-host with every backup and compare it after an incident or a
restore (RUNBOOK section 9); only a copy the attacker cannot reach proves the history was not rewritten.

**The choice is final** for a library in 0.5: the installer never switches it, and nzbd refuses a switched
configuration (`BACKEND_MISMATCH` / `LIBRARY_MISMATCH`). Moving a SQLite library to PostgreSQL is deferred (D37); if
you ever move by hand, the old `nzbd.sqlite` still holds password hashes, sealed TOTP secrets and emails: nzbd never
deletes it, so put it into an encrypted backup or delete it yourself.

**PostgreSQL rules that keep the guarantees** (all shipped and asserted by the project's deployment check): never mount the
owner secret (the `setup_secrets` folder) or the socket volume into anything else, never give `postgres` a network or a
published port, never set `PG*`/`SSL_CERT_*` variables for nzbd (it refuses them), never edit roles, grants or the
security block of `deploy/postgres/postgresql.conf` (the logging settings keep failing rows, password hashes and keys
out of the server log).

## Existing reverse proxy

When `install.sh` puts nzbd behind a proxy you already run (Traefik, nginx, Caddy ... in Docker), the bundled Caddy is
not used and these points replace its defaults. (Project decision D34.)

- **Two gates, one of them yours.** The outer login (Traefik basic auth: the dedicated `nzbd-auth` login or your own
  auth middleware) is the first gate, nzbd's password + TOTP the second. The installer proposes the outer login and
  warns when you decline it, more strongly when a certificate resolver suggests an internet-facing entrypoint: without
  it nzbd faces whoever reaches the proxy with its own login only, which contradicts "LAN only" above.
- **The network decides who can bypass the first gate.** The outer login only covers requests that go through the
  proxy. Every container on the network nzbd joins can open `http://nzbd:8080` (or its address) directly:
  - **Choice 1, a new dedicated network** (created `internal`): only the proxy and nzbd are on it. No container can
    bypass the proxy, nzbd has no route out. **Recommended: the strongest isolation.**
  - **Choice 2, an existing shared network** (for example the Traefik network every routed app joins): accepted as an
    opt-in exception to SEC-041. Every other container on it reaches nzbd's login, `/api/v1/nzb` and `/healthz`
    without the outer login, so a compromised neighbour app only faces nzbd's own password + TOTP (and its throttling).
    If the network is not internal, nzbd also has a route to the internet; the app still opens no outbound connection
    (D3). The installer says so, asks (default no) and repeats the warning on every re-run.
  - **Choice 3**: nzbd stays on its internal `back` network and your proxy joins it.
- **Pin the proxy's address.** nzbd trusts `X-Forwarded-For`/`X-Forwarded-Proto` only from the proxy address stored as
  `NZBD_PROXY_TRUSTED_IP`. Give your proxy that address with `ipv4_address` in its compose file (the installer prints
  the snippet and warns when the current address is not pinned). Otherwise, after the proxy is re-created with another
  address, nzbd sees the proxy as the client of every request: the per-IP rate limits become shared by everyone, the
  login lock keyed on (account, client address) becomes per account (anyone who reaches the login can keep you locked
  out), and a container that later takes the old address is trusted. A blank answer has the same effect permanently.
- **Body limits, idle upstream connections and logs (T143).** Allow 321 MiB on `/upload` (a UI batch) and 65 MiB on
  `/api/v1/nzb`; with nginx also `proxy_request_buffering off;` on `/upload`. nzbd closes a keep-alive connection idle
  for 10 s, so the proxy must drop idle upstream connections within 8 s (Traefik:
  `serversTransport.forwardingTimeouts.idleConnTimeout: 8s`; Caddy: `transport http { keepalive 8s }`), or some
  requests fail with a 502. Redact the request URI, `Referer`, `Cookie`, `Authorization`, `X-Api-Key` and
  `X-Csrf-Token` in its access and error logs.
- **Headers middlewares.** A Traefik `headers` middleware *sets* each header it defines and so replaces nzbd's
  stricter value (`Content-Security-Policy`, the second defence against hostile NZB text, `Referrer-Policy:
  no-referrer`, `X-Frame-Options: DENY`, `Permissions-Policy`, ...). The installer pre-fills the middleware your other
  routers use most. **Run the header audit after every change of the proxy's middlewares:**

  ```
  cd deploy && ./audit-headers.sh https://nzbd.example.org --user admin
  ```

  It compares what the proxy delivers for `/login` with `nzbd security-headers` (OK / CHANGED / MISSING, HSTS with
  `max-age` >= 180 days, `Server`/`X-Powered-By` as INFO; exit 0 all OK, 1 findings, 2 could not check). A CHANGED
  header is your decision, not an error of nzbd: keep it only if you want it. With an outer login pass `--user`: curl
  prompts for the password (never on the command line), because the proxy's own 401 page does not carry nzbd's headers.
- **`/healthz`** is excluded from the generated Traefik router (``Host(`site`) && !Path(`/healthz`)``), so it gets
  Traefik's 404 from outside; Docker's healthcheck runs inside the container.
