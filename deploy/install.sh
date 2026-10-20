#!/usr/bin/env bash
# Interactive installer for the nzbd production stack (docs/QUICK_INSTALL.md, docs/INSTALL.md).
#
# What it does, in order: checks Docker, asks a few questions (among them the database: SQLite, the default, or
# PostgreSQL, and the UID:GID nzbd runs as: yours by default), writes deploy/.env (mode 0600), creates the data
# directories and the volumes directory (keys, state, certificates; plain host folders, no Docker volumes) owned by that
# UID:GID, generates the TOTP key
# and, with PostgreSQL, the database passwords (once, never shown), builds and starts the stack (PostgreSQL: the
# database first, then the one-shot `setup` service applies the schema), waits until it is healthy,
# exports the proxy root certificate and creates your user. If you already run a reverse proxy in Docker (Traefik,
# nginx, Caddy, ...) it can use that instead of the bundled Caddy: nzbd joins the network you pick (e.g. the one your
# Traefik compose defines) with a static IP you choose. The compose file you run, deploy/compose.yaml, is generated
# from the templates in deploy/compose-example/ and your answers.
#
# Safe to re-run: an existing .env is kept unless you say otherwise, an existing TOTP key or database password is never
# overwritten, a re-run never switches the database backend, nothing is deleted. nzbd starts a NEW library: an earlier private
# install found here is left untouched (its data directory is never used; import NZB files with `nzbd import`).
# Secrets: the proxy password is read without echo, goes to Docker over stdin (never argv, never written to disk) and
# only a bcrypt hash lands in .env.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,18p' "${BASH_SOURCE[0]##*/}" | sed 's/^# \{0,1\}//'
  exit 0
fi

c_b=""; c_g=""; c_y=""; c_r=""; c_0=""
if [ -t 1 ]; then c_b=$'\033[1m'; c_g=$'\033[32m'; c_y=$'\033[33m'; c_r=$'\033[31m'; c_0=$'\033[0m'; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s== %s%s\n' "$c_b" "$*" "$c_0"; }
ok()   { printf '%s ok%s %s\n' "$c_g" "$c_0" "$*"; }
warn() { printf '%swarn%s %s\n' "$c_y" "$c_0" "$*" >&2; }
die()  { printf '%sFAIL%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }

# ask VAR "Question" "default"  (empty answer = default)
ask() {
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [ -n "$__def" ]; then read -r -p "$__q [$__def]: " __ans; else read -r -p "$__q: " __ans; fi
  printf -v "$__var" '%s' "${__ans:-$__def}"
}
yesno() { # yesno "Question" default(y|n)
  local __ans __def=${2:-n}
  read -r -p "$1 [$([ "$__def" = y ] && echo Y/n || echo y/N)]: " __ans
  __ans=${__ans:-$__def}
  case "$__ans" in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

# ---- IPv4 helpers (subnets of Docker networks, static addresses) ------------------------------------
valid_ip() { # dotted quad, no leading zeros (they would be read as octal by $(( )))
  local IFS=. o
  case "$1" in '' | *[!0-9.]*) return 1 ;; esac # before the unquoted split below: no glob characters get through
  set -- $1
  [ $# -eq 4 ] || return 1
  for o; do
    case "$o" in '' | *[!0-9]* | 0?*) return 1 ;; esac
    [ "$o" -le 255 ] || return 1
  done
}
# valid_cidr: a.b.c.d/len with len 8..30. Every subnet read from .env or Docker passes it before shell arithmetic
# (ip2int): bash evaluates array subscripts such as x[$(cmd)] inside $(( )), so nothing else may get there.
valid_cidr() {
  local len
  case "$1" in */*) ;; *) return 1 ;; esac
  valid_ip "${1%/*}" || return 1
  len=${1#*/}
  case "$len" in '' | *[!0-9]* | 0?*) return 1 ;; esac
  [ "$len" -ge 8 ] && [ "$len" -le 30 ]
}
ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
int2ip() { echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"; }
cidr_overlap() { # cidr1 cidr2: success when the ranges overlap
  local a=${1%/*} al=${1#*/} b=${2%/*} bl=${2#*/} m
  m=$(( al < bl ? al : bl ))
  [ $(( $(ip2int "$a") >> (32 - m) )) -eq $(( $(ip2int "$b") >> (32 - m) )) ]
}
host_in_subnet() { # ip cidr: success when ip is a usable host address of cidr (not the network or broadcast address)
  local ip net len size off
  ip=$(ip2int "$1"); net=$(ip2int "${2%/*}"); len=${2#*/}
  [ "$len" -ge 8 ] && [ "$len" -le 30 ] || return 1
  size=$(( 1 << (32 - len) )); net=$(( net & ~(size - 1) & 0xFFFFFFFF )); off=$(( ip - net ))
  [ "$off" -gt 0 ] && [ "$off" -lt $(( size - 1 )) ]
}
used_subnets() { # IPv4 subnets of every Docker network except our own
  docker network ls -q | xargs -r docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null |
    while read -r name rest; do
      [ "$name" = nzbd_back ] && continue
      for s in $rest; do
        case "$s" in *:*) ;; */*) case "${s#*/}" in '' | *[!0-9]*) ;; *) ! valid_ip "${s%/*}" || echo "$s" ;; esac ;; esac
      done
    done
}
free_24() { # first 10.N.30.0/24 (N 200-250) that overlaps no existing Docker network nor the CIDRs given as arguments
  local used n cand clash u
  used="$(used_subnets || true) $*"
  for n in $(seq 200 250); do
    cand="10.$n.30.0/24"; clash=0
    for u in $used; do if cidr_overlap "$cand" "$u"; then clash=1; break; fi; done
    if [ "$clash" = 0 ]; then echo "$cand"; return 0; fi
  done
  return 1
}
net_subnet() { # first IPv4 subnet of a Docker network
  docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$1" 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+/[0-9]+$' | head -n 1
}
net_used_ips() { # gateway + addresses of the containers currently attached (nzbd's own container excluded: re-runs)
  docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' "$1" 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' || true
  docker network inspect -f '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}' "$1" 2>/dev/null |
    awk -v own="$(name_prefix)" '$1 != own && $1 !~ /^nzbd[-_]nzbd[-_]/ { sub(/\/.*/, "", $2); if ($2 != "") print $2 }' || true # network not created yet
}
first_free_ip() { # cidr used-ip...: lowest free host address from .2 on
  local cidr=$1 net len size i cand; shift
  net=$(ip2int "${cidr%/*}"); len=${cidr#*/}; size=$(( 1 << (32 - len) )); net=$(( net & ~(size - 1) & 0xFFFFFFFF ))
  for i in $(seq 2 $(( size - 2 > 1024 ? 1024 : size - 2 ))); do
    cand=$(int2ip $(( net + i )))
    case " $* " in *" $cand "*) ;; *) echo "$cand"; return 0 ;; esac
  done
  return 1
}

# ---- the container user nzbd runs as (T128) ---------------------------------------------------------
# valid_id N: a decimal UID or GID from 1 to 2147483646: digits only (no sign, no blank), no leading zero (no octal
# surprise in a later test), and never 0. 0 is root: nzbd never runs as root (SEC-040; serve refuses it too). The
# length test comes first so the numeric test never sees an overflowing value. 2147483647 and above are left out
# (some tools treat them as negative or as "no user"). Reserved (review 44 M2): 999 is PostgreSQL's own user, which
# pg_hba.conf lets in as the database SUPERUSER by peer authentication on the socket nzbd mounts; 65532 is the
# proxy's user and 65534 is "nobody". Same rule in volperms.sh and postgres/gen-secrets.sh.
IDS_RULE="two numbers from 1 to 2147483646; not 0 (root), 999 (PostgreSQL's superuser by peer authentication), 65532 (the proxy) or 65534 (nobody)"
valid_id() {
  case "$1" in '' | *[!0-9]* | 0* | 999 | 65532 | 65534) return 1 ;; esac
  [ "${#1}" -le 10 ] && [ "$1" -le 2147483646 ]
}
# valid_ids "UID:GID": exactly two valid ids. A single number is refused on purpose: whether it should mean UID:UID or
# the user's primary group is a guess, and a wrong group silently locks the operator out of the data directory.
valid_ids() {
  case "$1" in *:*:*) return 1 ;; ?*:?*) valid_id "${1%%:*}" && valid_id "${1#*:}" ;; *) return 1 ;; esac
}
# docker_remaps: Docker runs rootless or with userns-remap (review 44 I1). Container uid N is then a subordinate uid on
# the host, not the account with uid N, so "your own IDs" would not give you the data directory. No Docker = no.
docker_remaps() {
  local so
  so=$(docker info -f '{{json .SecurityOptions}}' 2>/dev/null || true)
  case "$so" in *name=rootless* | *name=userns*) return 0 ;; *) return 1 ;; esac
}
# propose_ids: sets PROPOSED (UID:GID) and PROPOSED_WHY: 'user' = the IDs of whoever runs this script; 'sudo' = run
# through sudo, so the IDs of the user who called sudo (SUDO_UID / SUDO_GID); 'root' = run as root (or with GID 0)
# without a usable sudo caller, 'reserved' = the running account has an id nzbd must not use (999, 65532, 65534),
# 'remap' = rootless Docker or userns-remap: in all three the image's own user 10001:10001 (no host account usually
# has it).
propose_ids() {
  local u g
  u=$(id -u 2>/dev/null || true); g=$(id -g 2>/dev/null || true)
  if docker_remaps; then
    PROPOSED=10001:10001; PROPOSED_WHY=remap
  elif [ "$u" = 0 ] && valid_id "${SUDO_UID:-}" && valid_id "${SUDO_GID:-}"; then
    PROPOSED="$SUDO_UID:$SUDO_GID"; PROPOSED_WHY=sudo
  elif valid_id "$u" && valid_id "$g"; then
    PROPOSED="$u:$g"; PROPOSED_WHY=user
  elif [ "$u" = 0 ] || [ "$g" = 0 ]; then
    PROPOSED=10001:10001; PROPOSED_WHY=root
  else
    PROPOSED=10001:10001; PROPOSED_WHY=reserved
  fi
}
# ask_ids DEFAULT: asks until the answer is a valid UID:GID (Enter = DEFAULT); sets NZBD_UID and NZBD_GID. The answer is
# taken as typed (IFS=: blanks are refused, not trimmed). End of input stops the installer instead of looping or guessing.
ask_ids() {
  local ans
  while :; do
    IFS= read -r -p "UID:GID for nzbd [$1]: " ans || die "no answer for the UID:GID (end of input); nothing was written."
    ans=${ans:-$1}
    if valid_ids "$ans"; then NZBD_UID=${ans%%:*}; NZBD_GID=${ans#*:}; return 0; fi
    warn "not usable: type UID:GID, e.g. 1000:1000: $IDS_RULE."
  done
}
# say_ids_intro: the explanation printed before ask_ids (PROPOSED / PROPOSED_WHY set by propose_ids).
say_ids_intro() {
  local who
  say
  say "${c_b}Container user${c_0}: nzbd runs as an unprivileged numeric user ID (UID) and group ID (GID). The"
  say "storage folder is owned by it, so the host account with that UID can read and add files in the"
  say "data directory without sudo."
  case "$PROPOSED_WHY" in
    sudo)
      who=$(printf '%s' "${SUDO_USER:-}" | tr -cd 'A-Za-z0-9._-')
      say "Detected: you ran this through sudo; the user who called sudo${who:+ ($who)} has $PROPOSED." ;;
    user)
      who=$(id -un 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)
      say "Detected: you${who:+ ($who)} run this script as $PROPOSED." ;;
    remap)
      say "Detected: Docker runs rootless or with userns-remap here. A container UID is then NOT the host account with"
      say "that number (it maps to a subordinate UID), so your own IDs would not let you manage the data directory."
      say "The image's own user 10001:10001 is proposed." ;;
    reserved)
      say "Detected: your account's UID or GID is one nzbd must not use (999, 65532 or 65534; see below), so the"
      say "image's own user 10001:10001 is proposed instead." ;;
    *)
      say "Detected: you run this as root. nzbd never runs as root (UID or GID 0), so the image's own user"
      say "10001:10001 is proposed instead (no host account has it: use sudo to look into the data directory), or type"
      say "the UID:GID of the account that should own the files." ;;
  esac
  say "Best: an account used by nothing else. That account can read and change the whole library (database, NZBs,"
  say "backups); media containers (SABnzbd, Sonarr, ...) often run as 1000:1000, so do not share their IDs."
  say "Press Enter to accept, or type another UID:GID ($IDS_RULE)."
}

# new_password_hash WHAT: asks for (or generates) the outer-login password and sets PW, GENERATED and HASH (bcrypt from
# the pinned caddy image; the password reaches Docker over stdin only, never argv or disk).
new_password_hash() {
  if yesno "Generate a random 24-character $1 password for you?" y; then
    PW=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 24 || true)
    [ "${#PW}" -eq 24 ] || die "could not generate a password."
    GENERATED=1
  else
    while :; do
      read -r -s -p "$1 password (min 20 characters, not echoed): " PW; echo
      read -r -s -p "Repeat: " PW2; echo
      [ "$PW" = "$PW2" ] || { warn "passwords differ."; continue; }
      [ "${#PW}" -ge 20 ] || { warn "use at least 20 characters (basic auth is not rate-limited)."; continue; }
      break
    done
  fi
  say "Hashing the password (bcrypt, takes a moment)..."
  # This container sees the plaintext password: no network, read-only root, unprivileged user, no capabilities except
  # NET_BIND_SERVICE, which the image's caddy binary carries as a file capability (without it in the bounding set the
  # exec itself fails; it is meaningless with --network none). '|| true' so a failing docker run reaches the message
  # below instead of ending the script silently (set -e + pipefail).
  HASH=$(printf '%s\n' "$PW" | docker run --rm -i --network none --read-only --user 65534:65534 --cap-drop ALL \
    --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true "$CADDY_IMG" caddy hash-password 2>/dev/null |
    head -n 1 | tr -d '\r') || true
  case "$HASH" in '$2a$'*) ;; *) die "could not hash the password with Docker (is the caddy image pullable?)." ;; esac
}

# Traefik conventions of the containers already running here, so nzbd's router matches them. nzbd's own router (a
# re-run) is left out. traefik_values SUFFIX: values of traefik.http.routers.<r>.<SUFFIX>, most used first.
# Labels of other containers (including labels baked into third-party images) are untrusted display data: control
# characters are removed before anything is printed or suggested, and every value is charset-checked before use.
traefik_labels() {
  docker ps -q | xargs -r docker inspect -f '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' 2>/dev/null |
    tr -d '\000-\011\013-\037\177' | grep '^traefik\.http\.routers\.' | grep -v '^traefik\.http\.routers\.nzbd\.' || true
}
traefik_values() {
  traefik_labels | sed -n "s/^traefik\.http\.routers\.[^.=]*\.$1=//p" | sort | uniq -c | sort -rn | awk '{print $2}'
}
traefik_middlewares() { # "count name" per middleware, most used first
  traefik_labels | sed -n 's/^traefik\.http\.routers\.[^.=]*\.middlewares=//p' | tr ',' '\n' | tr -d ' ' | awk 'NF' |
    sort | uniq -c | sort -rn | awk '{print $1, $2}'
}

# proxy_kind CONTAINER: traefik | nginx | caddy | other, from the image name and, for a renamed or self-built image,
# the image title label and the command it runs.
proxy_kind() {
  local s
  s=$(docker inspect -f '{{.Config.Image}} {{index .Config.Labels "org.opencontainers.image.title"}} {{.Path}} {{join .Config.Cmd " "}}' "$1" 2>/dev/null |
    tr -d '\000-\037\177' | tr 'A-Z' 'a-z')
  case "$s" in *traefik*) echo traefik ;; *nginx*) echo nginx ;; *caddy*) echo caddy ;; *) echo other ;; esac
}

# ---- .env values: read back and re-validated --------------------------------------------------------
ENVF=.env
get() { sed -n "s/^$1=//p" "$ENVF" | head -n 1 | sed "s/^'//; s/'\$//"; }
# The short fixed names of the containers (<prefix>, <prefix>-proxy, <prefix>-db) and of the PostgreSQL socket volume.
# Default prefix nzbd; NZBD_NAME_PREFIX in .env changes it (tests, a second stack).
name_prefix() { local v; v=$(get NZBD_NAME_PREFIX 2>/dev/null); printf '%s' "${v:-nzbd}"; }
# abs_path P: P as an absolute path without a trailing slash, relative paths against this directory.
abs_path() { case "$1" in /*) printf '%s' "${1%/}" ;; *) printf '%s/%s' "$PWD" "${1#./}" ;; esac; }
# volumes_dir: NZBD_VOLUMES_DIR from $ENVF, absolute (default ./storage).
volumes_dir() { local v; v=$(get NZBD_VOLUMES_DIR 2>/dev/null); abs_path "${v:-./storage}"; }
# pg_data_dir: NZBD_PG_DATA_DIR from $ENVF (PostgreSQL's database files), absolute; default <volumes dir>/pg_data.
pg_data_dir() { local v; v=$(get NZBD_PG_DATA_DIR 2>/dev/null); if [ -n "$v" ]; then abs_path "$v"; else printf '%s/pg_data' "$(volumes_dir)"; fi; }
bad_env() { die "$1 in $ENVF is invalid ($2). Fix or delete the line and re-run."; }
# check_env: the answers are checked when typed, but .env is operator-edited (and can be copied or corrupted), so every
# value is checked again with the same rules before it reaches a Traefik rule, a Go template, YAML or arithmetic.
check_env() {
  local k v bad
  # Review 36 L1: `get` reads the FIRST `KEY=` line, docker compose the LAST assignment, and compose also accepts
  # `export KEY=`, leading blanks and blanks around `=`. Any such spelling would let a value bypass the rules below,
  # so only plain `KEY=value` lines (and comments/blank lines) are accepted, each key once.
  bad=$(grep -nvE '^[A-Z][A-Z0-9_]*=|^[[:space:]]*(#|$)' "$ENVF" | head -n 1 | cut -d: -f1 || true)
  [ -z "$bad" ] || die "$ENVF line $bad is not a plain KEY=value line (no 'export', no spaces around '='). Fix it and re-run."
  bad=$(sed -n 's/^\([A-Z][A-Z0-9_]*\)=.*/\1/p' "$ENVF" | sort | uniq -d | head -n 1)
  [ -z "$bad" ] || die "$bad appears more than once in $ENVF (docker compose would use the last one). Keep one line and re-run."
  v=$(get NZBD_SITE); case "$v" in *[!a-z0-9.-]* | -*) bad_env NZBD_SITE "lowercase letters, digits, dots and dashes" ;; esac
  for k in NZBD_PROXY_USER NZBD_EXTERNAL_PROXY NZBD_PROXY_NETWORK; do
    v=$(get "$k"); case "$v" in *[!A-Za-z0-9._-]* | -*) bad_env "$k" "letters, digits, . _ -" ;; esac
  done
  v=$(get NZBD_EXTERNAL_PROXY_KIND); case "$v" in '' | traefik | nginx | caddy | other) ;; *) bad_env NZBD_EXTERNAL_PROXY_KIND "traefik, nginx, caddy or other" ;; esac
  v=$(get NZBD_PROXY_NETMODE); case "$v" in '' | new | existing | join) ;; *) bad_env NZBD_PROXY_NETMODE "new, existing or join" ;; esac
  for k in NZBD_TRAEFIK_ENTRYPOINT NZBD_TRAEFIK_RESOLVER NZBD_TRAEFIK_TLS_OPTIONS NZBD_TRAEFIK_AUTH; do
    v=$(get "$k"); case "$v" in *[!A-Za-z0-9._@-]*) bad_env "$k" "letters, digits, . _ @ -" ;; esac
  done
  v=$(get NZBD_TRAEFIK_MIDDLEWARES); case "$v" in *[!A-Za-z0-9._@,-]*) bad_env NZBD_TRAEFIK_MIDDLEWARES "comma-separated names" ;; esac
  v=$(get NZBD_TRAEFIK_AUTH_USERS)
  [ -z "$v" ] || printf '%s\n' "$v" | grep -Eqx '[A-Za-z0-9._-]+:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' ||
    bad_env NZBD_TRAEFIK_AUTH_USERS "user:bcrypt-hash"
  v=$(get NZBD_HTTPS_PORT); case "$v" in *[!0-9]*) bad_env NZBD_HTTPS_PORT "a port number" ;; esac
  v=$(get NZBD_BIND); case "$v" in *[!0-9A-Fa-f.:]*) bad_env NZBD_BIND "an IP address" ;; esac
  for k in NZBD_PROXY_IP NZBD_PROXY_NET_IP NZBD_PROXY_TRUSTED_IP; do
    v=$(get "$k"); [ -z "$v" ] || [ "$k:$v" = NZBD_PROXY_TRUSTED_IP:none ] || valid_ip "$v" || bad_env "$k" "an IPv4 address"
  done
  for k in NZBD_BACK_SUBNET NZBD_BACK_RANGE NZBD_PROXY_NET_SUBNET; do
    v=$(get "$k"); [ -z "$v" ] || valid_cidr "$v" || bad_env "$k" "an IPv4 subnet a.b.c.d/8..30"
  done
  v=$(get NZBD_NAME_PREFIX)
  case "$v" in '' | [a-z0-9]*) ;; *) bad_env NZBD_NAME_PREFIX "lowercase letters, digits, _ and -, starting with a letter or digit" ;; esac
  case "$v" in *[!a-z0-9_-]*) bad_env NZBD_NAME_PREFIX "lowercase letters, digits, _ and -, starting with a letter or digit" ;; esac
  [ "${#v}" -le 30 ] || bad_env NZBD_NAME_PREFIX "at most 30 characters"
  for k in NZBD_DATA_DIR NZBD_VOLUMES_DIR NZBD_PG_DATA_DIR; do
    v=$(get "$k"); case "$v" in *[!A-Za-z0-9._/-]*) bad_env "$k" "letters, digits, . _ - and / only" ;; esac
  done
  v=$(get NZBD_DB_BACKEND); case "$v" in '' | sqlite | postgres) ;; *) bad_env NZBD_DB_BACKEND "sqlite or postgres" ;; esac
  v=$(get NZBD_LOG_FORMAT); case "$v" in '' | pretty | json) ;; *) bad_env NZBD_LOG_FORMAT "pretty or json" ;; esac
  # T128: the container user, when present (need_ids below requires it where a stack is rendered or deployed).
  for k in NZBD_UID NZBD_GID; do
    v=$(get "$k"); [ -z "$v" ] || valid_id "$v" || bad_env "$k" "one of $IDS_RULE"
  done
  # Review 33 L1: the stack runs the images built from THIS tree under their :local names. A registry name here would
  # run an unpinned image on the next 'docker compose pull' / 'up --pull always'; a gate tag would mix the live stack
  # with the test gates' namespace. Only the local names are accepted (or no line at all).
  v=$(get NZBD_IMAGE); case "$v" in '' | nzbd:local) ;; *) bad_env NZBD_IMAGE "only nzbd:local (or remove the line): the stack runs the image built from this tree" ;; esac
  v=$(get NZBD_PROXY_IMAGE); case "$v" in '' | nzbd-proxy:local) ;; *) bad_env NZBD_PROXY_IMAGE "only nzbd-proxy:local (or remove the line)" ;; esac
}

# The images of the rendered stack never come from the caller's shell (review 33 L1): the gates export NZBD_IMAGE /
# NZBD_PROXY_IMAGE with per-run tags, and one left exported in an operator's shell must not leak into compose.yaml.
shell_image_warning() {
  if [ -n "${NZBD_IMAGE:-}" ] || [ -n "${NZBD_PROXY_IMAGE:-}" ]; then
    warn "NZBD_IMAGE / NZBD_PROXY_IMAGE are set in this shell (${NZBD_IMAGE:-}${NZBD_PROXY_IMAGE:+ ${NZBD_PROXY_IMAGE}}): ignored;"
    warn "the stack always uses nzbd:local and nzbd-proxy:local, built from this tree."
  fi
}

# need_ids: both NZBD_UID and NZBD_GID are in $ENVF (values already checked by check_env). Without them nothing is
# rendered: there is no silent default for the user that will own the data (owner decision 2026-10-16, fresh starts
# only; the interactive run asks for a missing value instead of calling this first).
need_ids() {
  [ -n "$(get NZBD_UID)" ] && [ -n "$(get NZBD_GID)" ] ||
    die "$ENVF lacks NZBD_UID and/or NZBD_GID (the UID:GID nzbd runs as): add both, e.g. NZBD_UID=$(id -u) and NZBD_GID=$(id -g), or run ./install.sh in a terminal to be asked."
}
# env_ids: NZBD_UID / NZBD_GID from $ENVF (after check_env and need_ids).
env_ids() { NZBD_UID=$(get NZBD_UID); NZBD_GID=$(get NZBD_GID); }

# render_compose DATA_FOR_COMPOSE CONF [overlay]: the self-contained compose file for the values in $ENVF (templates +
# the PostgreSQL overlay when NZBD_DB_BACKEND=postgres + the existing-proxy override + the generated overlay), as
# resolved by 'docker compose config'. --profile setup keeps the one-shot services (still gated by their profile in the
# output); the bundled proxy, disabled by a profile with an existing proxy, is left out, and with it every network
# nothing uses.
render_compose() {
  local args=(-f compose-example/compose.yaml)
  [ "$(get NZBD_DB_BACKEND)" != postgres ] || args+=(-f compose-example/compose.postgres.yaml)
  [ -z "$(get NZBD_EXTERNAL_PROXY)" ] || args+=(-f compose-example/compose.external-proxy.yaml)
  [ -z "${3:-}" ] || args+=(-f "$3")
  # The process environment wins over --env-file in compose: pinning the local image names here means no spelling in
  # .env or in the shell can change them (review 33 L1, review 36 L1). Same for the container user (T128): only the
  # re-validated values of .env reach the file, never an NZBD_UID left exported in the shell.
  env_ids
  env -u COMPOSE_FILE -u COMPOSE_PROFILES NZBD_IMAGE=nzbd:local NZBD_PROXY_IMAGE=nzbd-proxy:local \
    NZBD_UID="$NZBD_UID" NZBD_GID="$NZBD_GID" NZBD_NAME_PREFIX="$(name_prefix)" \
    NZBD_DATA_DIR="$1" NZBD_VOLUMES_DIR="$(volumes_dir)" NZBD_PG_DATA_DIR="$(pg_data_dir)" NZBD_LOG_FORMAT="$(get NZBD_LOG_FORMAT)" NZBD_CONFIG="$2" docker compose --env-file "$ENVF" "${args[@]}" --profile setup config
}

# emit_overlay: the compose overlay for an existing proxy on a shared network (choices 1 and 2), from NETNAME, APP_IP,
# TIP, EXT_KIND, SITE, TEP, TRES, TOPT, TMW, TAUTH and NZBD_TRAEFIK_AUTH_USERS (all validated); sets 'chain'.
# '!override' replaces the template's 'networks: [back]' (a plain override would merge the two), so nzbd is only on
# the shared network; the network key is the network's real name. Needs Docker Compose 2.24.4 or later.
emit_overlay() {
  local users
  printf '# Generated by install.sh from .env: nzbd is only on the network shared with your proxy.\n'
  printf 'services:\n  nzbd:\n    networks: !override\n'
  printf '      "%s":\n        ipv4_address: "%s"\n' "$NETNAME" "$APP_IP"
  printf '    environment:\n'
  printf "      NZBD__server__trusted_proxies: '[%s]'\n" "${TIP:+\"$TIP\"}"
  chain=""
  if [ "$EXT_KIND" = traefik ]; then
    printf '    labels:\n'
    printf '      traefik.enable: "true"\n'
    printf '      traefik.docker.network: "%s"\n' "$NETNAME"
    # /healthz gets Traefik's own 404 from outside, like the bundled Caddyfile (Docker's healthcheck runs inside).
    printf '      traefik.http.routers.nzbd.rule: "Host(`%s`) && !Path(`/healthz`)"\n' "$SITE"
    printf '      traefik.http.routers.nzbd.entrypoints: "%s"\n' "${TEP:-websecure}"
    printf '      traefik.http.routers.nzbd.tls: "true"\n'
    if [ -n "$TRES" ]; then printf '      traefik.http.routers.nzbd.tls.certresolver: "%s"\n' "$TRES"; fi
    if [ -n "$TOPT" ]; then printf '      traefik.http.routers.nzbd.tls.options: "%s"\n' "$TOPT"; fi
    printf '      traefik.http.routers.nzbd.service: "nzbd"\n'
    # Basic auth first (like the bundled proxy, nothing reaches nzbd unauthenticated), then the other middlewares.
    # Order kept, duplicates dropped (e.g. the reused auth middleware also typed in the list).
    chain=$(printf '%s,%s' "$TAUTH" "$TMW" | tr ',' '\n' | awk 'NF && !seen[$0]++' | paste -sd, -)
    if [ -n "$chain" ]; then printf '      traefik.http.routers.nzbd.middlewares: "%s"\n' "$chain"; fi
    if [ "$TAUTH" = nzbd-auth ]; then
      users=$(get NZBD_TRAEFIK_AUTH_USERS)
      case "$users" in *:'$2a$'*) ;; *) die "NZBD_TRAEFIK_AUTH_USERS in .env is not 'user:bcrypt-hash'; re-run without keeping .env." ;; esac
      # '$$' is compose's escape for a literal '$' (bcrypt hashes are full of them); removeheader keeps the
      # credentials away from nzbd, like 'header_up -Authorization' in the bundled Caddyfile.
      printf '      traefik.http.middlewares.nzbd-auth.basicauth.users: "%s"\n' "${users//\$/\$\$}"
      printf '      traefik.http.middlewares.nzbd-auth.basicauth.removeheader: "true"\n'
    fi
    printf '      traefik.http.services.nzbd.loadbalancer.server.port: "8080"\n'
  fi
  printf 'networks:\n  "%s":\n    name: "%s"\n    external: true\n' "$NETNAME" "$NETNAME"
}

# Test hook for scripts/deploy_check.sh static (review 27 I4): print the overlay a run would generate from the
# .env-shaped FILE, after the same re-validation. Asks nothing and reads no Docker state.
if [ "${1:-}" = --print-overlay ]; then
  [ $# -eq 2 ] || die "usage: install.sh --print-overlay ENVFILE"
  case "$2" in /*) ENVF=$2 ;; *) ENVF="$OLDPWD/$2" ;; esac
  [ -f "$ENVF" ] || die "no such file: $ENVF"
  check_env
  SITE=$(get NZBD_SITE); EXT_KIND=$(get NZBD_EXTERNAL_PROXY_KIND); NETNAME=$(get NZBD_PROXY_NETWORK)
  APP_IP=$(get NZBD_PROXY_NET_IP); NSUB=$(get NZBD_PROXY_NET_SUBNET); TIP=$(get NZBD_PROXY_TRUSTED_IP)
  TEP=$(get NZBD_TRAEFIK_ENTRYPOINT); TRES=$(get NZBD_TRAEFIK_RESOLVER); TOPT=$(get NZBD_TRAEFIK_TLS_OPTIONS)
  TMW=$(get NZBD_TRAEFIK_MIDDLEWARES); TAUTH=$(get NZBD_TRAEFIK_AUTH)
  [ "$TIP" != none ] || TIP=""
  [ -n "$SITE" ] && [ -n "$NETNAME" ] && [ -n "$APP_IP" ] && [ -n "$NSUB" ] ||
    die "--print-overlay needs NZBD_SITE, NZBD_PROXY_NETWORK, NZBD_PROXY_NET_IP and NZBD_PROXY_NET_SUBNET."
  host_in_subnet "$APP_IP" "$NSUB" || die "NZBD_PROXY_NET_IP is not a host address of NZBD_PROXY_NET_SUBNET."
  emit_overlay
  exit 0
fi

# same_dir A B: the two paths name one directory (parents resolved when they exist, else compared without ./ and /).
same_dir() {
  local a b
  # Resolve through the PARENT: a data directory is owned by the container user with mode 0700, so it may be closed.
  a=$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)/$(basename "$1") || a=""
  b=$(cd "$(dirname "$2")" 2>/dev/null && pwd -P)/$(basename "$2") || b=""
  [ -z "$a" ] || [ "$a" != "$b" ] || return 0
  a=${1#./}; a=${a%/}; b=${2#./}; b=${b%/}
  [ "$a" = "$b" ]
}
# legacy_env: the .env in $ENVF was written by an earlier private installer (every current installer writes NZBD_DB_BACKEND), so an old
# library lives here (D37: never upgraded, never touched).
legacy_env() { [ -f "$ENVF" ] && ! grep -q '^NZBD_DB_BACKEND=' "$ENVF"; }
# Test hook for scripts/deploy_check.sh static: 'legacy' or 'current' for the .env-shaped FILE.
if [ "${1:-}" = --print-library ]; then
  [ $# -eq 2 ] || die "usage: install.sh --print-library ENVFILE"
  case "$2" in /*) ENVF=$2 ;; *) ENVF="$OLDPWD/$2" ;; esac
  if legacy_env; then echo legacy; else echo current; fi
  exit 0
fi

# Test hook for scripts/deploy_check.sh static (review 33 L1, T116): print the compose file a run would generate from the
# .env-shaped FILE (bundled proxy or an existing proxy joined to nzbd_back, either backend), after the same
# re-validation. Asks nothing; needs only 'docker compose config'.
if [ "${1:-}" = --print-compose ]; then
  [ $# -eq 2 ] || die "usage: install.sh --print-compose ENVFILE"
  case "$2" in /*) ENVF=$2 ;; *) ENVF="$OLDPWD/$2" ;; esac
  [ -f "$ENVF" ] || die "no such file: $ENVF"
  check_env
  case "$(get NZBD_PROXY_NETMODE)" in new | existing) die "--print-compose renders the bundled proxy or choice 3 only (use --print-overlay)." ;; esac
  need_ids
  shell_image_warning
  d=$(get NZBD_DATA_DIR); d=${d:-./storage/data}; case "$d" in /*) ;; *) d="$PWD/${d#./}" ;; esac
  render_compose "$d" "$PWD/config/nzbd.toml"
  exit $?
fi

# random_invite_path: "/join-" + 12 random [a-z0-9] (T135). Shares no prefix with a built-in route; nzbd validates it
# at startup anyway (INVITE_PATH_INVALID).
random_invite_path() {
  local r
  r=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12 || true)
  [ ${#r} -eq 12 ] || return 1
  printf '/join-%s\n' "$r"
}
# emit_settings INVITE_PATH: the host-editable settings file of a fresh install: every example setting commented out,
# plus the generated security.invite_path (T135; it only hides the invitation page from scanners, the one-time code is
# the protection, docs/OPERATOR_SECURITY.md).
emit_settings() {
  printf '# nzbd settings, mounted read-only into the container at /etc/nzbd/config.toml. Created once by\n'
  printf '# install.sh, never overwritten. Uncomment and change what you need, then apply with\n'
  printf '#   docker compose restart nzbd        (check first: docker compose exec nzbd /nzbd config check)\n'
  printf '# Every key: docs/CONFIGURATION.md. Never put secrets here (keys are files in the secrets folder of the storage folder).\n'
  printf '# install.sh sets server.listen, server.trusted_proxies and server.allowed_hosts as environment variables,\n'
  printf '# which override this file: change those by re-running ./install.sh.\n'
  printf '# Example: several accounts with invitations = under [security] below, add the line: multi_user = true\n'
  printf '# The invitation page then lives at the random invite_path below (not at /invite); change it freely.\n\n'
  sed -e '/^#/d' -e '/^invite_path *=/d' -e 's/^\([a-z_][a-z0-9_]* *=\)/# \1/' config/example.toml |
    awk -v p="$1" '{ print } $0 == "[security]" { print "invite_path = \"" p "\"   # generated by install.sh: the invitation page (multi_user = true)" }'
}
# Test hook for scripts/deploy_check.sh static (T135): print the settings file a fresh install would create.
if [ "${1:-}" = --print-settings ]; then
  p=$(random_invite_path) || die "cannot read random bytes from /dev/urandom."
  emit_settings "$p"
  exit 0
fi

# Test hooks for scripts/deploy_check.sh (T128). --propose-ids prints the UID:GID the questions would propose for the
# user running it, and why (user | sudo | root). --ask-ids runs the real question loop on stdin (a terminal is not
# required here) and prints the accepted UID:GID; it ends with an error at end of input.
if [ "${1:-}" = --propose-ids ]; then
  propose_ids; echo "$PROPOSED $PROPOSED_WHY"; exit 0
fi
if [ "${1:-}" = --ask-ids ]; then
  propose_ids; say_ids_intro >&2; ask_ids "$PROPOSED"; echo "$NZBD_UID:$NZBD_GID"; exit 0
fi

# shared_network_ok NAME: nzbd may join a network that is not internal only with the operator's explicit consent (owner
# decision D34, review 27 M1). Every container on such a network reaches nzbd without the proxy's outer login, and
# nzbd gets a route out. An internal network passes silently.
SHARED_ACK=""
shared_network_ok() {
  [ "$(docker network inspect -f '{{.Internal}}' "$1" 2>/dev/null)" != true ] || return 0
  warn "'$1' is NOT an internal network. If nzbd joins it:"
  warn "  - every other container on '$1' can reach nzbd directly (http://nzbd:8080 or its address) WITHOUT going"
  warn "    through '${EXT_NAME:-your proxy}', so without its outer login: only nzbd's own password + TOTP stop them;"
  warn "  - nzbd gets a route to the internet (nzbd itself never opens an outbound connection)."
  warn "  Strongest isolation: choice 1 with a new name = a dedicated internal network shared only by your proxy and"
  warn "  nzbd. Details: docs/OPERATOR_SECURITY.md, 'Existing reverse proxy'."
  yesno "Continue with '$1' anyway?" n || return 1
  SHARED_ACK=$1
}

[ -t 0 ] || die "this installer is interactive: run it from a terminal."

# Review 44 I3: the project (and so the volume names) comes from the generated compose.yaml ('name: nzbd'), never from
# a COMPOSE_PROJECT_NAME left in the shell, which would point the compose calls at other volumes than the checks.
if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
  warn "COMPOSE_PROJECT_NAME is set in this shell: ignored (the project is the 'name:' of compose.yaml)."
  unset COMPOSE_PROJECT_NAME
fi

# ---- 1. preflight ---------------------------------------------------------------------------------
step "1/9 Checking this host"
command -v docker >/dev/null 2>&1 || die "docker not found. Install Docker Engine or Docker Desktop first."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable (is it running? are you in the docker group?)."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 ('docker compose') is required."
# 2.24.4 is the first release with the '!override' YAML tag used for the shared proxy network (see below).
cv=$(docker compose version --short 2>/dev/null | sed 's/^v//; s/[^0-9.].*//')
[ "$(printf '%s\n' 2.24.4 "$cv" | sort -V | head -n 1)" = 2.24.4 ] || die "Docker Compose $cv is too old: 2.24.4 or later is required."
[ -f compose-example/compose.yaml ] && [ -f Dockerfile ] && [ -f Dockerfile.proxy ] || die "run this script from the deploy/ directory of the nzbd tree."
# install.sh, volperms.sh and compose-example/ change together: a lone install.sh copied over an older tree would render
# the old templates (Docker volumes instead of the volumes directory).
grep -q 'NZBD_VOLUMES_DIR' compose-example/compose.yaml && grep -q '/as/' volperms.sh ||
  die "compose-example/ or volperms.sh is older than this install.sh: copy the WHOLE deploy/ directory of the same release (or the whole tree), not install.sh alone."
ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), compose $(docker compose version --short 2>/dev/null || echo '?')"

# The same digest-pinned caddy image the proxy is built from (hash-password, CA export, chown helper).
CADDY_IMG=$(sed -n 's/^FROM \(caddy:2@sha256:[0-9a-f]\{64\}\) AS tools.*/\1/p' Dockerfile.proxy | head -n 1)
CADDY_IMG=${CADDY_IMG:-caddy:2}

say
say "${c_b}What should this run do?${c_0}"
say "  1) Generate the configuration and deploy (data directories, build, key, start, your user)"
say "  2) Only generate the configuration (.env + compose files) and stop: nothing is created, built or started;"
say "     review it, then re-run ./install.sh, keep the .env and choose 1 to deploy it"
ask RUNCHOICE "Choose" "1"
case "$RUNCHOICE" in 1) DEPLOY=1 ;; 2) DEPLOY=0 ;; *) die "answer 1 or 2." ;; esac
NEED_NET=""

# ---- 2. configuration -----------------------------------------------------------------------------
step "2/9 Configuration (.env)"
write_env=1
# A fresh start (D37): a .env written by an earlier private installer (every current installer writes NZBD_DB_BACKEND) means an old
# library lives next to this script. It is never upgraded and never touched: a new data directory is used.
LEGACY=0; OLD_DATA=""; PREV_BACKEND=""
if [ -f .env ]; then
  PREV_BACKEND=$(get NZBD_DB_BACKEND)
  if legacy_env; then
    LEGACY=1; OLD_DATA=$(get NZBD_DATA_DIR); OLD_DATA=${OLD_DATA:-./data}
    warn "this directory holds the configuration of an earlier private nzbd install (data directory: $OLD_DATA)."
    say "nzbd starts a NEW, empty library. It does not upgrade an earlier database: it refuses one (LEGACY_DATABASE) and"
    say "never modifies it. Nothing of the earlier install is changed or deleted; its data directory is not used."
    say "Its containers in this directory are replaced by the new stack when you deploy (keep a backup of the old data)."
    say "To bring your NZB files over afterwards: copy them into the new watch folder, or use"
    say "'docker compose exec nzbd /nzbd import <dir>' (copies, never moves; RUNBOOK section 5)."
    say "Your old .env is kept as .env.bak.<time>; the questions below are asked again."
    yesno "Set up a new library here?" y || die "nothing was changed."
  elif yesno "Keep the existing .env and skip these questions?" y; then
    write_env=0
  fi
  [ "$write_env" = 0 ] || warn ".env already exists: it is saved as .env.bak.<time> and rewritten."
fi

MODE=bundled; EXT_NAME=""; EXT_KIND=""; GENERATED=0
NETMODE="join"; NETNAME=""; TEP=websecure; TRES=""; LOGIN_USER=""
if [ "$write_env" = 1 ]; then
  say "Press Enter to accept the value in brackets."
  ask SITE "Host name your browsers will use (lowercase, no port)" "nzbd.lan"
  case "$SITE" in *[!a-z0-9.-]* | "" | -*) die "invalid host name '$SITE' (lowercase letters, digits, dots and dashes)." ;; esac

  # ---- existing reverse proxy? ------------------------------------------------------------------
  say
  say "${c_b}Reverse proxy${c_0}: nzbd needs HTTPS and an outer login in front of it."
  cands=$(docker ps --format '{{.Names}}|{{.Image}}' | tr -d '\000-\011\013-\037\177' | grep -Ei 'traefik|nginx|caddy|haproxy' | grep -Evi "^nzbd[-_]|nzbd-proxy|^$(name_prefix)(-proxy|-db)?\\|" || true)
  # Traefik is the recommended existing proxy (the installer configures its router, TLS and login through labels):
  # Traefik containers are listed first, so the default answer "1" picks one when there is any.
  cands=$({ printf '%s\n' "$cands" | grep -i traefik; printf '%s\n' "$cands" | grep -vi traefik; } | awk 'NF' || true)
  hasproxy=n
  if [ -n "$cands" ]; then
    say "Found running proxy-like containers on this host (Traefik first: recommended, configured for you):"
    printf '%s\n' "$cands" | awk -F'|' '{t = (tolower($2) ~ /traefik/) ? "  <- Traefik, recommended" : ""; printf "    %d) %s  (%s)%s\n", NR, $1, $2, t}'
    hasproxy=y
  else
    say "No running proxy-like container (Traefik, nginx, Caddy, HAProxy) was found on this host."
  fi
  say "Answer no to install the bundled Caddy proxy instead (HTTPS with its own CA + a login)."
  PUSER="admin"; BIND=127.0.0.1; PORT=443; HASH=unused
  if yesno "Do you already run a reverse proxy in Docker and want nzbd behind it?" "$hasproxy"; then
    MODE=external
    if [ -n "$cands" ]; then
      ask EXT_NAME "Container name (or number from the list above)" "1"
      case "$EXT_NAME" in
        *[!0-9]* | "") ;;
        *) EXT_NAME=$(printf '%s\n' "$cands" | sed -n "${EXT_NAME}p" | cut -d'|' -f1) ;;
      esac
    else
      ask EXT_NAME "Name of your proxy container" ""
    fi
    { [ -n "$EXT_NAME" ] && docker inspect "$EXT_NAME" >/dev/null 2>&1; } || die "no running container named '$EXT_NAME'."
    EXT_KIND=$(proxy_kind "$EXT_NAME")
    ok "using '$EXT_NAME' ($EXT_KIND); the bundled proxy will not be installed"
    # Only Traefik is configured by this installer (labels: router, TLS, middlewares, basic auth); for any other proxy
    # every Traefik question is skipped and you add the route to nzbd in your proxy's own configuration.
    if [ "$EXT_KIND" != traefik ]; then
      say "'$EXT_NAME' is not Traefik: the Traefik questions are skipped. After the deploy, point your proxy at nzbd"
      say "(http://<nzbd address>:8080, Host '$SITE'); the summary at the end shows the address (docs/INSTALL.md)."
    fi
    say "Your proxy becomes the outer gate: enable TLS there, and an auth layer if you want one."
    say "nzbd still requires its own password + TOTP."
    PUSER=unused

    # Networks the proxy is already on come first: with a compose-managed proxy (e.g. a Traefik stack that defines
    # its own network) that is the network nzbd should join.
    pnets=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$EXT_NAME" 2>/dev/null |
      tr ' ' '\n' | awk 'NF && $0 !~ /^(bridge|host|none|nzbd_back)$/' || true)
    say
    say "${c_b}How should '$EXT_NAME' reach nzbd?${c_0}"
    say "  1) Create a NEW dedicated Docker network now (internal: nzbd keeps no internet access and only containers"
    say "     you attach to it can reach nzbd); you then add it as an external network in your proxy's compose file"
    say "  2) Attach nzbd to an EXISTING network (e.g. the one your proxy compose already defines); if it is shared"
    say "     with other apps, they can reach nzbd without the proxy's login (you are warned and asked)"
    say "  3) Keep nzbd on its private network and join your proxy container to it (quick, not persistent)"
    if [ -n "$pnets" ]; then ask NCHOICE "Choose" "2"; else ask NCHOICE "Choose" "1"; fi
    case "$NCHOICE" in
      1)
        NETMODE=new
        ask NETNAME "Name of the new network" "nzbd_proxy"
        case "$NETNAME" in *[!A-Za-z0-9._-]* | "" | -*) die "invalid network name." ;; esac
        if docker network inspect "$NETNAME" >/dev/null 2>&1; then
          say "A network named '$NETNAME' already exists: nzbd joins it as it is (nothing is created)."
          shared_network_ok "$NETNAME" || die "aborted: re-run and pick a name that does not exist yet (choice 1), or choice 2."
        fi
        ;;
      2)
        NETMODE=existing
        others=$(docker network ls --format '{{.Name}}|{{.Driver}}' | awk -F'|' '$2=="bridge"{print $1}' | grep -Evx 'bridge|nzbd_back' || true)
        nets=$({ printf '%s\n' "$pnets"; printf '%s\n' "$others"; } | awk 'NF && !seen[$0]++')
        if [ -n "$nets" ]; then
          say "Existing networks (subnet; * = '$EXT_NAME' is attached to it):"
          i=0
          while read -r n; do
            i=$((i + 1))
            mark=" "; case " $(printf '%s ' $pnets)" in *" $n "*) mark="*" ;; esac
            printf '    %d)%s %s  (%s)\n' "$i" "$mark" "$n" "$(net_subnet "$n" || true)"
          done <<<"$nets"
          ask NETNAME "Network name (or number)" "1"
          case "$NETNAME" in
            *[!0-9]* | "") ;;
            *) NETNAME=$(printf '%s\n' "$nets" | sed -n "${NETNAME}p") ;;
          esac
        else
          ask NETNAME "Network name" ""
        fi
        case "$NETNAME" in *[!A-Za-z0-9._-]* | "" | -*) die "invalid network name." ;; esac
        docker network inspect "$NETNAME" >/dev/null 2>&1 || die "no Docker network named '$NETNAME'. Start your proxy stack first so it exists (a network 'proxy' in a compose project 'traefik' is named 'traefik_proxy' unless it sets 'name:'), then re-run."
        shared_network_ok "$NETNAME" || die "aborted."
        ;;
      *) NETMODE="join" ;;
    esac
    case "$NETNAME" in *[!A-Za-z0-9._-]*) die "invalid network name." ;; esac
    if [ "$EXT_KIND" = traefik ] && [ "$NETMODE" != join ]; then
      say
      say "${c_b}Traefik router for nzbd${c_0} (suggestions = what your other containers use)"
      d=$(traefik_values entrypoints | head -n 1 || true)
      ask TEP "Entrypoint for HTTPS" "${d:-websecure}"
      d=$(traefik_values 'tls\.options' | head -n 1 || true)
      ask TOPT "TLS options (blank = Traefik's default)" "$d"
      d=$(traefik_values 'tls\.certresolver' | head -n 1 || true)
      ask TRES "Certificate resolver (blank = your default TLS setup)" "$d"
      case "$TEP$TOPT$TRES" in *[!A-Za-z0-9._@-]*) die "invalid entrypoint/TLS options/resolver name." ;; esac

      mws=$(traefik_middlewares || true)
      auth_mws=$(printf '%s\n' "$mws" | awk '$2 ~ /[Aa]uth/ {print $2}')
      d=$(printf '%s\n' "$mws" | awk '$2 !~ /[Aa]uth/ {print $2; exit}')
      if [ -n "$mws" ]; then
        say "Middlewares used by your other routers:"
        printf '%s\n' "$mws" | awk '{printf "    %-32s %d router(s)\n", $2, $1}'
      fi
      ask TMW "Middlewares for nzbd, comma-separated, in order (blank = none; basic auth is asked next)" "$d"
      TMW=$(printf '%s' "$TMW" | tr -d ' ')
      case "$TMW" in *[!A-Za-z0-9._@,-]*) die "invalid middleware list." ;; esac
      if [ -n "$TMW" ]; then
        warn "a Traefik 'headers' middleware SETS each response header it defines, replacing nzbd's stricter value:"
        warn "Content-Security-Policy (strict; the second defence against hostile NZB text), Referrer-Policy (no-referrer),"
        warn "X-Frame-Options (DENY), Permissions-Policy, Cross-Origin-*-Policy, X-Content-Type-Options, Cache-Control."
        warn "Headers it does not define keep nzbd's value. HSTS: nzbd adds it only when it trusts the proxy's HTTPS report."
        warn "This installer cannot see what '$TMW' sets: after the deploy, compare with ./audit-headers.sh https://$SITE"
      fi

      say
      say "${c_b}Outer login${c_0} (HTTP basic auth at Traefik, like an .htaccess): a second password before nzbd's own"
      say "login + TOTP. Upload API clients (POST /api/v1/nzb) then have to send it as well."
      TAUTH=""; TAUSERS=""
      while :; do
        if yesno "Protect nzbd with basic auth at Traefik?" y; then
          ach=2
          if [ -n "$auth_mws" ]; then
            say "  1) Reuse an existing auth middleware: $(printf '%s ' $auth_mws)"
            say "  2) Create a dedicated login for nzbd (middleware 'nzbd-auth', defined on nzbd's own labels)"
            ask ach "Choose" "1"
          fi
          if [ "$ach" = 1 ]; then
            ask TAUTH "Auth middleware to reuse" "$(printf '%s\n' "$auth_mws" | head -n 1)"
            case "$TAUTH" in *[!A-Za-z0-9._@-]* | "") die "invalid middleware name." ;; esac
          else
            TAUTH=nzbd-auth
            ask LOGIN_USER "Login user name" "admin"
            case "$LOGIN_USER" in *[!A-Za-z0-9._-]* | "") die "invalid user name (letters, digits, . _ -)." ;; esac
            new_password_hash "login"
            TAUSERS="$LOGIN_USER:$HASH"
            HASH=unused # NZBD_PROXY_HASH belongs to the bundled proxy, which is not used here
          fi
          break
        fi
        # Declining the outer gate contradicts OPERATOR_SECURITY "LAN only" when Traefik faces the internet (review 27 L1).
        warn "without an outer login, whoever reaches '$TEP' on Traefik reaches nzbd's login page directly."
        if [ -n "$TRES" ]; then
          warn "The certificate resolver '$TRES' usually means an ACME certificate, i.e. an entrypoint reachable from the"
          warn "internet: nzbd would then face the internet behind its own password + TOTP only."
        fi
        warn "docs/OPERATOR_SECURITY.md ('LAN only', 'Existing reverse proxy') recommends the outer login."
        if yesno "Continue WITHOUT an outer login?" n; then break; fi
      done
    fi
  else
    ask PUSER "Proxy login user name" "admin"
    case "$PUSER" in *[!A-Za-z0-9._-]* | "") die "invalid user name (letters, digits, . _ -)." ;; esac
    ask BIND "Address to publish on (this host's LAN IP; 127.0.0.1 = this machine only)" "127.0.0.1"
    [ "$BIND" != "0.0.0.0" ] || warn "0.0.0.0 publishes on every interface: do not use it on a host that faces the internet."
    ask PORT "HTTPS port" "443"
    case "$PORT" in *[!0-9]* | "") die "port must be a number." ;; esac
  fi
  # One folder for everything nzbd keeps (owner decision): the library in <folder>/data and the key, state and
  # certificate folders next to it (<folder>/secrets, state, caddy; PostgreSQL: setup_secrets, pg_secrets). All plain
  # host folders, no Docker volumes, so 'docker compose down -v' and 'docker volume prune' cannot delete them.
  # NZBD_DATA_DIR and NZBD_VOLUMES_DIR in .env are derived from it (an operator can still split them by hand).
  if [ "$LEGACY" = 1 ]; then rdef=./storage-new; else rdef=./storage; fi
  say
  say "${c_b}Storage folder${c_0}: everything nzbd keeps goes in one folder on this host: the library (data/: NZB files, search"
  say "index, SQLite database) and the keys, state and proxy certificates (secrets/, state/, caddy/). Plain folders, not"
  say "Docker volumes: 'docker compose down -v' and 'docker volume prune' cannot delete them. Put it on a disk with space"
  say "and include the whole folder in your backups (docs/RUNBOOK.md)."
  while :; do
    ask ROOT "Storage folder" "$rdef"
    case "$ROOT" in "" | *[!A-Za-z0-9._/-]*) warn "use letters, digits, '.', '_', '-' and '/' only."; continue ;; esac
    ROOT=${ROOT%/}; [ -n "$ROOT" ] || ROOT=/
    DATA="${ROOT%/}/data"; VOLS=$ROOT
    if [ "$LEGACY" = 1 ] && same_dir "$DATA" "$OLD_DATA"; then
      warn "'$DATA' is the data directory of an earlier install: it is never reused. Pick another folder."; continue
    fi
    break
  done

  # ---- the container user (T128): proposes the IDs of whoever runs this script -------------------------
  propose_ids
  say_ids_intro
  ask_ids "$PROPOSED"

  # ---- database backend (D35 b, D37: SQLite default, PostgreSQL optional; chosen once) -----------------
  say
  say "${c_b}Database${c_0}"
  say "  1) SQLite (default): one container, the database is a file in the data directory; nothing else to run."
  say "     Right for a personal or family library (designed for about a million releases)."
  say "  2) PostgreSQL: adds a hardened PostgreSQL 18 container (no network, socket only, non-root), the one-shot"
  say "     'setup' service and generated database passwords. The more secure choice for a shared or internet-facing"
  say "     install: the database also binds a compromised nzbd (it cannot rewrite the audit history or delete"
  say "     accounts), which SQLite cannot do (docs/OPERATOR_SECURITY.md, 'Choosing a backend')."
  say "  The choice is final for this library: switching later is not supported in 0.5."
  case "$PREV_BACKEND" in postgres) bdef=2 ;; *) bdef=1 ;; esac
  ask DBCHOICE "Choose" "$bdef"
  case "$DBCHOICE" in 1) DB_BACKEND=sqlite ;; 2) DB_BACKEND=postgres ;; *) die "answer 1 or 2." ;; esac
  PGDATA_DIR=""
  if [ "$DB_BACKEND" = postgres ]; then
    say "PostgreSQL keeps its database files in their own folder (created inside the one you choose; owned by PostgreSQL's"
    say "uid 999, mode 0700). Put it on a disk with space and fast I/O; it must not be inside the library (data/)."
    while :; do
      ask PGDATA_DIR "PostgreSQL database folder" "${VOLS%/}/pg_data"
      case "$PGDATA_DIR" in "" | *[!A-Za-z0-9._/-]*) warn "use letters, digits, '.', '_', '-' and '/' only."; continue ;; esac
      pa=$(abs_path "$PGDATA_DIR"); da=$(abs_path "$DATA")
      case "$pa/" in "$da/"*) warn "the PostgreSQL directory must not be the data directory or inside it."; continue ;; esac
      break
    done
  fi
  # A re-run never switches an existing library (ARCHITECTURE 13.5): the SQLite -> PostgreSQL move is deferred (D37).
  if [ -n "$PREV_BACKEND" ] && [ "$PREV_BACKEND" != "$DB_BACKEND" ]; then
    die "this install uses $PREV_BACKEND; switching the backend of an existing library is not supported in 0.5 (the move script is deferred). Answer $bdef, or deploy a new library from another directory."
  fi

  if [ "$MODE" = bundled ]; then
    say
    say "The proxy password is the outer gate (the app has its own login + TOTP behind it)."
    new_password_hash proxy
    LOGIN_USER=$PUSER
  fi

  case "${NZBD_NAME_PREFIX:-}" in *[!a-z0-9_-]* | [_-]*) die "NZBD_NAME_PREFIX must be lowercase letters, digits, _ and -, starting with a letter or digit." ;; esac
  _np=${NZBD_NAME_PREFIX:-}
  [ "${#_np}" -le 30 ] || die "NZBD_NAME_PREFIX must be at most 30 characters."
  if [ -f .env ]; then cp -p .env ".env.bak.$(date +%Y%m%d%H%M%S)"; fi
  umask 077
  {
    printf '# Written by deploy/install.sh. Values containing $ MUST stay single-quoted.\n'
    printf 'NZBD_SITE=%s\n' "$SITE"
    printf 'NZBD_PROXY_USER=%s\n' "$PUSER"
    printf "NZBD_PROXY_HASH='%s'\n" "$HASH"
    printf 'NZBD_BIND=%s\n' "$BIND"
    printf 'NZBD_HTTPS_PORT=%s\n' "$PORT"
    printf 'NZBD_DATA_DIR=%s\n' "$DATA"
    printf '# Keys, state, proxy certificates and database files: plain host folders (not Docker volumes), see docs/RUNBOOK.md.\n'
    printf 'NZBD_VOLUMES_DIR=%s\n' "$VOLS"
    printf '# The UID:GID nzbd runs as (never 0); the data directory and the volumes directory belong to it. Chosen for a fresh\n'
    printf '# install: existing key directories are never re-owned (install.sh refuses directories of another user).\n'
    printf 'NZBD_UID=%s\n' "$NZBD_UID"
    printf 'NZBD_GID=%s\n' "$NZBD_GID"
    printf '# Database backend, chosen once (sqlite | postgres); a re-run never switches it.\n'
    printf 'NZBD_DB_BACKEND=%s\n' "$DB_BACKEND"
    [ -z "$PGDATA_DIR" ] || printf '# PostgreSQL database files (plain host folder, uid 999).\nNZBD_PG_DATA_DIR=%s\n' "$PGDATA_DIR"
    # Volume and container names are <prefix>_secrets, <prefix>, ...; only written when you chose a prefix
    # (NZBD_NAME_PREFIX=... ./install.sh), the default is nzbd.
    [ -z "${NZBD_NAME_PREFIX:-}" ] || printf 'NZBD_NAME_PREFIX=%s\n' "$NZBD_NAME_PREFIX"
    if [ "$MODE" = external ]; then
      printf '# Existing reverse proxy: the bundled proxy is disabled (compose-example/compose.external-proxy.yaml).\n'
      printf 'NZBD_EXTERNAL_PROXY=%s\n' "$EXT_NAME"
      printf 'NZBD_EXTERNAL_PROXY_KIND=%s\n' "$EXT_KIND"
      printf 'NZBD_PROXY_NETMODE=%s\n' "$NETMODE"
      printf 'NZBD_PROXY_NETWORK=%s\n' "$NETNAME"
      printf 'NZBD_TRAEFIK_ENTRYPOINT=%s\n' "$TEP"
      printf 'NZBD_TRAEFIK_RESOLVER=%s\n' "$TRES"
      printf 'NZBD_TRAEFIK_TLS_OPTIONS=%s\n' "${TOPT:-}"
      printf 'NZBD_TRAEFIK_MIDDLEWARES=%s\n' "${TMW:-}"
      printf 'NZBD_TRAEFIK_AUTH=%s\n' "${TAUTH:-}"
      printf "NZBD_TRAEFIK_AUTH_USERS='%s'\n" "${TAUSERS:-}"
    fi
  } >.env
  chmod 600 .env
  if [ "$MODE" = bundled ]; then ok ".env written (mode 0600, contains only the password hash)"; else ok ".env written (mode 0600)"; fi
  if [ "$GENERATED" = 1 ]; then
    say
    say "${c_b}Outer login at the proxy (shown once, store it in your password manager):${c_0}"
    say "    user:     $LOGIN_USER"
    say "    password: $PW"
    read -r -p "Press Enter when you have saved it... " _
  fi
  unset PW PW2 HASH TAUSERS
fi

# A kept .env without the container user (hand-written, or older): asked like a new install, then stored. No
# migration logic: the owner deploys fresh (decision 2026-10-16).
check_env
if [ -z "$(get NZBD_UID)" ] || [ -z "$(get NZBD_GID)" ]; then
  warn "$ENVF has no complete NZBD_UID / NZBD_GID: asking for it."
  propose_ids
  say_ids_intro
  ask_ids "$PROPOSED"
  # A fresh temporary file next to .env (mktemp: 0600, never an existing name or link), then one rename (review 44 I5).
  envtmp=$(mktemp ./.env.XXXXXX) || die "cannot write in $PWD."
  { grep -Ev '^NZBD_[UG]ID=' .env || true
    printf '# The UID:GID nzbd runs as (never 0); the data directory and the key volumes belong to it.\nNZBD_UID=%s\nNZBD_GID=%s\n' \
      "$NZBD_UID" "$NZBD_GID"; } >"$envtmp" || { rm -f "$envtmp"; die "cannot write in $PWD."; }
  chmod 600 "$envtmp" && mv -f "$envtmp" .env
  ok "NZBD_UID=$NZBD_UID and NZBD_GID=$NZBD_GID added to .env"
fi

# A kept .env from before the volumes directory existed: the keys then live in Docker volumes. Ask once and store the
# answer; the copy of the old volumes is done below, before anything is created (nothing is migrated silently).
if [ -z "$(get NZBD_VOLUMES_DIR)" ]; then
  warn "$ENVF has no NZBD_VOLUMES_DIR: asking for it."
  ask VOLS "Storage folder for the keys, state and certificates" "./storage"
  case "$VOLS" in "" | *[!A-Za-z0-9._/-]*) die "use letters, digits, '.', '_', '-' and '/' only." ;; esac
  envtmp=$(mktemp ./.env.XXXXXX) || die "cannot write in $PWD."
  { grep -Ev '^NZBD_VOLUMES_DIR=' .env || true
    printf '# Keys, state, proxy certificates and database files: plain host folders (not Docker volumes), see docs/RUNBOOK.md.\nNZBD_VOLUMES_DIR=%s\n' "$VOLS"; } >"$envtmp" ||
    { rm -f "$envtmp"; die "cannot write in $PWD."; }
  chmod 600 "$envtmp" && mv -f "$envtmp" .env
  ok "NZBD_VOLUMES_DIR=$VOLS added to .env"
fi

# Read the effective values back so the later steps and the summary match the file, after checking them again.
check_env
need_ids
env_ids
SITE=$(get NZBD_SITE); BIND=$(get NZBD_BIND); PORT=$(get NZBD_HTTPS_PORT); DATA=$(get NZBD_DATA_DIR)
SITE=${SITE:-nzbd.lan}; BIND=${BIND:-127.0.0.1}; PORT=${PORT:-443}; DATA=${DATA:-./storage/data}
DB_BACKEND=$(get NZBD_DB_BACKEND); DB_BACKEND=${DB_BACKEND:-sqlite}
VOLS_ABS=$(volumes_dir); PG_ABS=$(pg_data_dir)
EXT_NAME=$(get NZBD_EXTERNAL_PROXY); EXT_KIND=$(get NZBD_EXTERNAL_PROXY_KIND)
if [ -n "$EXT_NAME" ]; then MODE=external; else MODE=bundled; fi
# With an existing proxy on a shared network (choices 1 and 2) nzbd is ONLY on that network: the private network
# 'back' exists for the bundled proxy and for choice 3, so it is neither used nor created then.
NEEDS_BACK=1
if [ "$MODE" = external ]; then case "$(get NZBD_PROXY_NETMODE)" in new | existing) NEEDS_BACK=0 ;; esac; fi

# nzbd's private network defaults to 172.30.0.0/24. Docker refuses to create it when another network already uses an
# overlapping range ("networks have overlapping IPv4"), which is common on hosts that run other stacks. Pick a free
# /24 once and pin it in .env (the proxy address must be inside the subnet and outside the dynamic range).
if [ "$NEEDS_BACK" = 1 ] && [ -z "$(get NZBD_BACK_SUBNET)" ]; then
  used=$(used_subnets || true)
  subnet=172.30.0.0/24; conflict=0
  for u in $used; do if cidr_overlap "$subnet" "$u"; then conflict=1; fi; done
  if [ "$conflict" = 1 ]; then
    chosen=$(free_24 || true)
    [ -n "$chosen" ] || die "172.30.0.0/24 is taken and no free private /24 was found: set NZBD_BACK_SUBNET, NZBD_PROXY_IP and NZBD_BACK_RANGE in .env by hand (docs/INSTALL.md step 2)."
    base=${chosen%.0/24}
    {
      printf '# Chosen by install.sh: 172.30.0.0/24 overlaps another Docker network on this host.\n'
      printf 'NZBD_BACK_SUBNET=%s\n' "$chosen"
      printf 'NZBD_PROXY_IP=%s.2\n' "$base"
      printf 'NZBD_BACK_RANGE=%s.128/25\n' "$base"
    } >>.env
    warn "172.30.0.0/24 is used by another Docker network; using $chosen for nzbd's private network."
  fi
fi
PROXY_IP=$(get NZBD_PROXY_IP); PROXY_IP=${PROXY_IP:-172.30.0.2}

# ---- proxy network (existing proxy, choices 1 and 2) ----------------------------------------------
# nzbd joins a network that your proxy also uses; the proxy's compose file declares it as an external network.
if [ "$MODE" = external ]; then
  NETMODE=$(get NZBD_PROXY_NETMODE); NETMODE=${NETMODE:-join}
  NETNAME=$(get NZBD_PROXY_NETWORK); TEP=$(get NZBD_TRAEFIK_ENTRYPOINT); TRES=$(get NZBD_TRAEFIK_RESOLVER)
  TOPT=$(get NZBD_TRAEFIK_TLS_OPTIONS); TMW=$(get NZBD_TRAEFIK_MIDDLEWARES); TAUTH=$(get NZBD_TRAEFIK_AUTH)
fi
TIP=""
if [ "$MODE" = external ] && [ "$NETMODE" != join ]; then
  TIP=$(get NZBD_PROXY_TRUSTED_IP)
  if [ "$NETMODE" = new ]; then
    # The subnet is chosen once and kept in .env, so a generate-only run and the later deploy agree on it (the static
    # addresses below are inside it). The network itself is only created when deploying.
    NSUB=$(get NZBD_PROXY_NET_SUBNET)
    if [ -z "$NSUB" ]; then
      if docker network inspect "$NETNAME" >/dev/null 2>&1; then NSUB=$(net_subnet "$NETNAME" || true)
        [ -z "$NSUB" ] || valid_cidr "$NSUB" || die "the subnet $NSUB of '$NETNAME' is not usable here (an IPv4 /8 to /30 is required)."
      else NSUB=$(free_24 "$(get NZBD_BACK_SUBNET)") || die "no free private /24 found for the new network; create '$NETNAME' yourself and re-run with choice 2."
      fi
      [ -n "$NSUB" ] || die "network '$NETNAME' has no IPv4 subnet."
      printf 'NZBD_PROXY_NET_SUBNET=%s\n' "$NSUB" >>.env
    fi
    if [ -z "$TIP" ]; then
      # An existing network the proxy is already on: trust the proxy's real address there (it must be pinned, see the
      # snippet). A new network: the proxy gets .2, written into the snippet.
      TIP=$(docker inspect -f '{{with index .NetworkSettings.Networks "'"$NETNAME"'"}}{{.IPAddress}}{{end}}' "$EXT_NAME" 2>/dev/null || true)
      valid_ip "$TIP" || TIP=$(int2ip $(( $(ip2int "${NSUB%/*}") + 2 )))
      printf 'NZBD_PROXY_TRUSTED_IP=%s\n' "$TIP" >>.env
    fi
    if ! docker network inspect "$NETNAME" >/dev/null 2>&1; then
      if [ "$DEPLOY" = 1 ]; then
        docker network create --internal --subnet "$NSUB" "$NETNAME" >/dev/null
        ok "created internal network '$NETNAME' ($NSUB); give '$EXT_NAME' the fixed address $TIP on it (snippet below)"
      else
        NEED_NET="docker network create --internal --subnet $NSUB $NETNAME"
      fi
    fi
  elif [ -z "$TIP" ]; then
    # The trusted address must be static (review 27 L2): a proxy re-created with another address makes nzbd see the
    # proxy as the client of every request, and whoever later gets the old address is trusted for X-Forwarded-For.
    say
    say "nzbd trusts X-Forwarded-For/Proto only from your proxy's own address on '$NETNAME'. That address must be STATIC:"
    say "pin it in your proxy's compose file (ipv4_address, snippet at the end), or nzbd cannot tell clients apart."
    TIP=$(docker inspect -f '{{with index .NetworkSettings.Networks "'"$NETNAME"'"}}{{.IPAddress}}{{end}}' "$EXT_NAME" 2>/dev/null || true)
    if [ -n "$TIP" ]; then
      pinned=$(docker inspect -f '{{with index .NetworkSettings.Networks "'"$NETNAME"'"}}{{with .IPAMConfig}}{{.IPv4Address}}{{end}}{{end}}' "$EXT_NAME" 2>/dev/null || true)
      if [ "$pinned" = "$TIP" ]; then ok "'$EXT_NAME' has the pinned address $TIP on '$NETNAME'"
      else warn "'$EXT_NAME' has $TIP on '$NETNAME' now, but it is NOT pinned: add 'ipv4_address: $TIP' (snippet at the end)."; fi
    fi
    while :; do
      [ -n "$TIP" ] || ask TIP "Static IP of '$EXT_NAME' on '$NETNAME' (blank = do not trust forwarded headers)" ""
      if [ -z "$TIP" ]; then
        warn "without a trusted proxy address nzbd sees every request as coming from the proxy: the per-IP rate limits"
        warn "are shared by all clients, and the login lock keyed on (account, client address) becomes per account, so"
        warn "anyone who reaches the login (on a shared network: any container on it) can keep you locked out."
        if yesno "Continue without trusting the proxy?" n; then break; fi
        continue
      fi
      valid_ip "$TIP" && break
      warn "'$TIP' is not an IPv4 address."; TIP=""
    done
    printf 'NZBD_PROXY_TRUSTED_IP=%s\n' "${TIP:-none}" >>.env
  fi
  [ "$TIP" = none ] && TIP=""
  [ -z "$TIP" ] || valid_ip "$TIP" || die "invalid proxy IP '$TIP'."

  # nzbd gets a static address on the shared network (asked once, kept in .env). The address must be a host of the
  # network's subnet and not taken by the gateway, the proxy or a running container. Docker accepts a fixed address
  # only on a network created with an explicit subnet (compose 'ipam: config: - subnet:' or 'docker network create
  # --subnet'); keep it outside the network's ip_range if one is set so a dynamically addressed container cannot take it.
  [ "$NETMODE" = new ] || NSUB=$(net_subnet "$NETNAME" || true)
  [ -n "$NSUB" ] || die "network '$NETNAME' has no IPv4 subnet; give it one (ipam subnet) and re-run."
  valid_cidr "$NSUB" || die "the subnet $NSUB of '$NETNAME' is not usable here (an IPv4 /8 to /30 is required)."
  # A kept .env skips the questions, so the M1 warning is repeated (without a prompt) whenever the network is shared.
  if [ "$SHARED_ACK" != "$NETNAME" ] && docker network inspect "$NETNAME" >/dev/null 2>&1 &&
    [ "$(docker network inspect -f '{{.Internal}}' "$NETNAME" 2>/dev/null)" != true ]; then
    warn "'$NETNAME' is not an internal network: other containers on it reach nzbd without the proxy's outer login and"
    warn "nzbd has a route out (accepted at install; docs/OPERATOR_SECURITY.md, 'Existing reverse proxy')."
  fi
  APP_IP=$(get NZBD_PROXY_NET_IP)
  if [ -z "$APP_IP" ]; then
    taken=$( { net_used_ips "$NETNAME"; [ -z "$TIP" ] || echo "$TIP"; } | sort -u | tr '\n' ' ')
    sug=$(first_free_ip "$NSUB" $taken || true)
    say
    say "${c_b}Static IP of nzbd on '$NETNAME'${c_0} (subnet $NSUB)."
    say "Addresses in use there now: ${taken:-none} (stopped containers are not listed: check your own plan)."
    while :; do
      ask APP_IP "IP address for nzbd" "$sug"
      valid_ip "$APP_IP" || { warn "'$APP_IP' is not an IPv4 address."; continue; }
      host_in_subnet "$APP_IP" "$NSUB" || { warn "$APP_IP is not a usable host address of $NSUB."; continue; }
      case " $taken " in *" $APP_IP "*) warn "$APP_IP is already in use on '$NETNAME'."; continue ;; esac
      break
    done
    printf 'NZBD_PROXY_NET_IP=%s\n' "$APP_IP" >>.env
  fi
  valid_ip "$APP_IP" && host_in_subnet "$APP_IP" "$NSUB" || die "NZBD_PROXY_NET_IP=$APP_IP in .env is not a host address of '$NETNAME' ($NSUB); fix or remove the line and re-run."
  [ "$APP_IP" != "$TIP" ] || die "nzbd and the proxy cannot share the address $APP_IP."
  ok "nzbd will use the static address $APP_IP on '$NETNAME'"
  if [ -n "$TIP" ] && ! host_in_subnet "$TIP" "$NSUB"; then
    warn "the proxy address $TIP is not inside $NSUB: nzbd will not trust its X-Forwarded-For. Fix NZBD_PROXY_TRUSTED_IP in .env."
  fi

  # Overlay merged into compose.yaml below, rebuilt on every run from the values in .env (emit_overlay above).
  OVERLAY=$(mktemp ./.install-overlay.XXXXXX) || die "cannot write in $PWD."
  trap 'rm -f "$OVERLAY"' EXIT
  emit_overlay >"$OVERLAY"
fi

# ---- render deploy/compose.yaml -------------------------------------------------------------------
# One self-contained file (templates + .env + overlay, as resolved by 'docker compose config'), so every plain
# 'docker compose ...' in this directory runs exactly what was reviewed. Rewritten on every run.
step "Generating compose.yaml"
# Older installers selected the layered files with COMPOSE_FILE in .env; they now live in compose-example/ and a
# leftover COMPOSE_FILE would override compose.yaml. Rewrite in place (keeps the 0600 mode; no sed -i: macOS).
if grep -q '^COMPOSE_FILE=' .env; then
  (umask 077 && grep -v '^COMPOSE_FILE=' .env >.env.tmp && cat .env.tmp >.env && rm -f .env.tmp)
  ok "removed the obsolete COMPOSE_FILE line from .env"
fi
if [ -f compose.proxy-net.yaml ] && head -n 1 compose.proxy-net.yaml | grep -q '^# Generated by install.sh'; then
  rm -f compose.proxy-net.yaml
  ok "removed compose.proxy-net.yaml (written by an older installer; now part of compose.yaml)"
fi
# Host-editable settings file, mounted read-only at /etc/nzbd/config.toml (NZBD_CONFIG_FILE in the container, so
# serve and every 'docker compose exec nzbd /nzbd ...' read it). Created once from the example with every setting
# commented out; never overwritten. 0644: the container user (NZBD_UID) reads it and it holds no secrets.
CONF=config/nzbd.toml
# Never follow a symlink here: 'chmod a+r' below would widen its target (review 27 I3).
[ ! -L "$CONF" ] || die "$PWD/$CONF is a symbolic link; replace it with a regular file (the container reads it read-only) and re-run."
if [ ! -e "$CONF" ]; then
  INVITE_PATH=$(random_invite_path) || die "cannot read random bytes from /dev/urandom."
  emit_settings "$INVITE_PATH" >"$CONF.new"
  chmod 644 "$CONF.new" && mv "$CONF.new" "$CONF"
  ok "created $PWD/$CONF (your settings file; edit it on the host)"
  # Not a secret (T135): it only keeps the page away from scanners. Shown again by 'nzbd config check'.
  ok "invitation page: $INVITE_PATH (security.invite_path in $CONF; served once multi_user = true)"
fi
[ -f "$CONF" ] || die "$PWD/$CONF is not a regular file (a directory left by an earlier failed start?). Remove it and re-run."
chmod a+r "$CONF" 2>/dev/null || true

# The template's relative paths are relative to compose-example/, but NZBD_DATA_DIR in .env is relative to this
# directory: hand compose an absolute data path.
case "$DATA" in /*) DATA_FOR_COMPOSE=$DATA ;; *) DATA_FOR_COMPOSE="$PWD/${DATA#./}" ;; esac
shell_image_warning
rendered=$(render_compose "$DATA_FOR_COMPOSE" "$PWD/$CONF" "${OVERLAY:-}") || die "could not render the compose configuration (see above)."
if [ -f compose.yaml ] && ! head -n 1 compose.yaml | grep -q '^# Generated by deploy/install.sh'; then
  bak="compose.yaml.bak.$(date +%Y%m%d%H%M%S)"; cp -p compose.yaml "$bak"
  warn "an existing compose.yaml not written by this installer was saved as $bak"
fi
umask 077 # bundled proxy: holds the bcrypt hash of the proxy password, like .env
{
  printf '# Generated by deploy/install.sh from compose-example/ and .env. Do not edit: change .env or re-run ./install.sh.\n'
  printf '%s\n' "$rendered"
} >compose.yaml.new
mv compose.yaml.new compose.yaml
env -u COMPOSE_FILE -u COMPOSE_PROFILES NZBD_IMAGE=nzbd:local NZBD_PROXY_IMAGE=nzbd-proxy:local docker compose config -q || die "the generated compose.yaml is invalid (see above)."
ok "$PWD/compose.yaml written and valid"
# The written file must mount exactly the directory the checks below use.
NAMEP=$(name_prefix)
grep -qx "        source: $VOLS_ABS/secrets" compose.yaml || die "compose.yaml does not mount $VOLS_ABS/secrets as the key directory."

# ---- generate only: validate, show, stop ---------------------------------------------------------
if [ "$DEPLOY" = 0 ]; then
  step "Configuration generated (nothing was created, built or started)"
  say "  Settings:       $PWD/.env (mode 0600)"
  say "  Compose file:   $PWD/compose.yaml (templates: compose-example/)"
  say
  # The bcrypt hashes stay out of the terminal (scrollback, 'script' logs): they are in .env and compose.yaml (0600).
  sed -e 's/^\([[:space:]]*NZBD_PROXY_HASH:\).*/\1 <hidden: bcrypt hash, see .env>/' \
    -e 's/^\([[:space:]]*traefik\.http\.middlewares\.[A-Za-z0-9_-]*\.basicauth\.users:\).*/\1 <hidden: user:bcrypt hash, see .env>/' \
    -e 's/^/      /' compose.yaml
  say
  say "  Settings file:  $PWD/$CONF (edit on the host; docker compose restart nzbd)"
  say "  Runs as:        $NZBD_UID:$NZBD_GID (NZBD_UID:NZBD_GID in .env; never root)"
  say "  Data directory: $DATA (created and owned by $NZBD_UID:$NZBD_GID at deploy)"
  say "  Volumes dir:    $VOLS_ABS (keys, state, certificates; plain folders, created at deploy)"
  [ "$DB_BACKEND" != postgres ] || say "  PostgreSQL dir: $PG_ABS (database files, uid 999, created at deploy)"
  if [ "$DB_BACKEND" = postgres ]; then
    say "  Database:       PostgreSQL. At deploy: database passwords generated (dbsecrets), postgres started, schema"
    say "                  applied by the one-shot setup service, then nzbd started (docs/INSTALL.md)."
  else
    say "  Database:       SQLite ($DATA/nzbd.sqlite, created by nzbd at the first start)"
  fi
  [ -z "$NEED_NET" ] || say "  Network:        '$NETNAME' is created at deploy:  $NEED_NET"
  if [ "$MODE" = external ] && [ "$NETMODE" = join ]; then
    say "  Proxy:          '$EXT_NAME' is attached to nzbd_back as $PROXY_IP at deploy"
  fi
  say
  say "To deploy it: ./install.sh, answer 1, then keep the existing .env."
  exit 0
fi

# ---- 3. data directories --------------------------------------------------------------------------
# Fresh starts only (owner decision 2026-10-16): key directories left by an install that ran as another UID:GID are never
# re-owned. Checked before anything is changed (data directory included); the volperms step below refuses them too.
# Installs that kept the keys in Docker volumes (nzbd_nzbd_secrets, nzbd_secrets, ...) must copy them into the folders
# once: deploying now would silently create an empty key folder (a NEW TOTP key, locking every user out) next to them.
legacy_volumes() { # prints "<volume> <folder>" for the first old Docker volume whose folder does not exist yet
  local o dst
  for o in nzbd_nzbd_secrets:secrets nzbd_secrets:secrets nzbd_nzbd_state:state nzbd_state:state nzbd_nzbd_setup_secrets:setup_secrets \
    nzbd_setup_secrets:setup_secrets nzbd_caddy_data:caddy nzbd_caddy:caddy nzbd_pg_data:pg_data nzbd_pg_secrets:pg_secrets; do
    case "${o#*:}" in setup_secrets | pg_data | pg_secrets) [ "$DB_BACKEND" = postgres ] || continue ;; esac
    dst="$VOLS_ABS/${o#*:}"; [ "${o#*:}" != pg_data ] || dst=$PG_ABS
    if docker volume inspect "${o%%:*}" >/dev/null 2>&1 && [ ! -e "$dst" ]; then
      echo "${o%%:*} $dst"; return 0
    fi
  done
  return 1
}
if [ "$NAMEP" = nzbd ] && lv=$(legacy_volumes); then
  set -- $lv
  say "An older install keeps its data in the Docker volume '$1'; this version keeps it in the folder '$2'."
  say "Stop the old stack (docker compose stop), then copy every old volume once and re-run. For this volume:"
  say "  mkdir -p '$2' && docker run --rm -u 0 -v $1:/from:ro -v '$2':/to --entrypoint sh $CADDY_IMG -c 'cp -a /from/. /to/'"
  say "(old volume -> folder: nzbd_nzbd_secrets or nzbd_secrets -> secrets, nzbd_nzbd_state or nzbd_state -> state, nzbd_caddy_data or"
  say " nzbd_caddy -> caddy; PostgreSQL: nzbd_nzbd_setup_secrets or nzbd_setup_secrets -> setup_secrets, nzbd_pg_data -> $PG_ABS,"
  say " nzbd_pg_secrets -> pg_secrets. Skip the ones you do not have; the old volumes are left as a backup.)"
  die "old Docker volumes found; nothing was changed. Copy them (above), then re-run."
fi
foreign_volumes() { # prints the first existing key directory that holds files of another user
  local v
  for v in secrets state setup_secrets; do
    [ -d "$VOLS_ABS/$v" ] || continue
    if docker run --rm -u 0 --network none --read-only -e NZBD_UID="$NZBD_UID" -e NZBD_GID="$NZBD_GID" -v "$VOLS_ABS/$v:/v:ro" \
      --entrypoint sh "$CADDY_IMG" -c 'find /v -mindepth 1 ! -name .nzbd-volume \( ! -user "$NZBD_UID" -o ! -group "$NZBD_GID" \) | grep -q .'; then
      echo "$VOLS_ABS/$v"; return 0
    fi
  done
  return 1
}
if fv=$(foreign_volumes); then
  say "The directory '$fv' holds files of another UID:GID: an earlier install ran as another user. nzbd never"
  say "re-owns or deletes key directories. Either put that UID:GID back into NZBD_UID / NZBD_GID in $PWD/.env, or start"
  say "fresh: back up what you need (docs/RUNBOOK.md section 2), remove the old stack and that folder yourself, then"
  say "re-run ./install.sh."
  die "the key directories are not owned by $NZBD_UID:$NZBD_GID; nothing was changed."
fi

step "3/9 Data directories (owned by $NZBD_UID:$NZBD_GID)"
for d in watch store failed duplicates tmp backups; do mkdir -p "$DATA/$d" 2>/dev/null || true; done
DATA_ABS=$(cd "$DATA" 2>/dev/null && pwd) || die "cannot create '$DATA' (permissions?). Create it first or pick another path."
# chown -R on every run, as before T128 (modes and contents unchanged). The ids reach the helper as environment
# values (validated by check_env), never spliced into the script text.
# Review 44 L2: never under a running nzbd (it could swap paths during the recursion), and the helper gets the volperms
# profile: root with only CHOWN, DAC_OVERRIDE and FOWNER, read-only root, no network, no-new-privileges.
if [ -n "$(docker compose ps -q nzbd 2>/dev/null)" ]; then
  say "Stopping nzbd while its files are prepared (it is started again in step 7)..."
  docker compose stop nzbd
fi
docker run --rm -u 0 --network none --read-only --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges:true -e NZBD_UID="$NZBD_UID" -e NZBD_GID="$NZBD_GID" -v "$DATA_ABS:/d" \
  --entrypoint sh "$CADDY_IMG" -c 'mkdir -p /d/watch /d/store /d/failed /d/duplicates /d/tmp /d/backups &&
    chown -hR "$NZBD_UID:$NZBD_GID" /d && chmod -R u=rwX,go= /d' || die "could not hand $DATA_ABS to $NZBD_UID:$NZBD_GID (see above)."
ok "$DATA_ABS ready"
# The volumes directory: plain folders (created here as the invoking user; volperms below hands them over). Compose never
# creates them (create_host_path is off), so a deleted folder is an error, not a silent empty key directory.
vdirs="secrets state caddy"; [ "$DB_BACKEND" != postgres ] || vdirs="$vdirs setup_secrets pg_secrets"
mkdir -p "$VOLS_ABS" 2>/dev/null || die "cannot create '$VOLS_ABS' (permissions?). Create it first or pick another path."
for d in $vdirs; do mkdir -p "$VOLS_ABS/$d" 2>/dev/null || die "cannot create '$VOLS_ABS/$d' (permissions?)."; done
ok "$VOLS_ABS ready ($vdirs)"
if [ "$DB_BACKEND" = postgres ]; then
  mkdir -p "$PG_ABS" 2>/dev/null || die "cannot create '$PG_ABS' (permissions?). Create it first or pick another path."
  ok "$PG_ABS ready (PostgreSQL database files; volperms hands it to uid 999)"
fi

# ---- 4. images ------------------------------------------------------------------------------------
step "4/9 Building the images (5-10 minutes the first time; needs internet for this step only)"
docker compose build
ok "images built"

# ---- 5. TOTP key ----------------------------------------------------------------------------------
step "5/9 Key directories (owned by $NZBD_UID:$NZBD_GID) and TOTP encryption key"
# The one-shot volperms service hands nzbd's key folders (keys, state; PostgreSQL: the owner secret) to the container
# user and the proxy / PostgreSQL folders to their service users. A folder holding files of another user (an earlier install with another NZBD_UID) is refused, never
# re-owned or deleted (deploy/volperms.sh).
if ! docker compose --profile setup run --rm volperms; then
  say "The key directories belong to another UID:GID (an earlier install). nzbd never re-owns or deletes them. Either put"
  say "that UID:GID back into NZBD_UID / NZBD_GID in $PWD/.env, or start fresh: back up what you need, remove the old"
  say "stack and $VOLS_ABS yourself (this deletes the TOTP key and the database files; the data directory stays),"
  say "then re-run ./install.sh."
  die "the key directories are not owned by $NZBD_UID:$NZBD_GID; nothing was changed."
fi
ok "key directories owned by $NZBD_UID:$NZBD_GID"
# key_exists FILE / key_ok FILE: FILE is in the key directory / the container user can read it. Both run AS that user
# (volperms just gave it the directory; root without capabilities could not even enter the 0700 directory).
key_exists() {
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    -u "$NZBD_UID:$NZBD_GID" -v "$VOLS_ABS/secrets:/s:ro" --entrypoint test "$CADDY_IMG" -e "/s/$1" 2>/dev/null
}
key_ok() {
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    -u "$NZBD_UID:$NZBD_GID" -v "$VOLS_ABS/secrets:/s:ro" --entrypoint test "$CADDY_IMG" -r "/s/$1" 2>/dev/null
}
if key_exists nzbd_totp_key; then
  key_ok nzbd_totp_key || die "the TOTP key exists but $NZBD_UID:$NZBD_GID cannot read it; nothing was deleted (docs/RUNBOOK.md, Troubleshooting)."
  ok "TOTP key already exists (kept, readable by $NZBD_UID:$NZBD_GID)"
else
  docker compose --profile setup run --rm keygen
  key_ok nzbd_totp_key || die "the new TOTP key is not readable by $NZBD_UID:$NZBD_GID (see above)."
  ok "key generated"
  warn "BACK UP $VOLS_ABS/secrets now, separately from the database (docs/RUNBOOK.md section 2)."
fi

# ---- 6. database (PostgreSQL only) ----------------------------------------------------------------
step "6/9 Database"
if [ "$DB_BACKEND" = postgres ]; then
  # Passwords are generated once and never printed (an existing set is kept: the server's roles use it).
  docker compose --profile setup run --rm dbsecrets
  key_ok nzbd_db_password || die "the database password is not readable by $NZBD_UID:$NZBD_GID (see above)."
  docker compose up -d postgres
  say "Waiting for PostgreSQL (the first start initializes the database: up to 2 minutes)..."
  pgid=$(docker compose ps -q postgres); pst=starting
  for _ in $(seq 1 60); do
    pst=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$pgid" 2>/dev/null || echo unknown)
    [ "$pst" = healthy ] && break
    sleep 3
  done
  [ "$pst" = healthy ] || die "postgres is '$pst'. See: docker compose logs postgres   (docs/RUNBOOK.md, Troubleshooting)"
  ok "postgres is healthy"
  # Review 36 M1: never migrate under a running nzbd (it would keep writing with the old semantics). A re-run (an
  # upgrade) stops it here; step 7 starts the new one. `setup` itself refuses while app-role sessions exist.
  if [ -n "$(docker compose ps -q nzbd 2>/dev/null)" ]; then
    say "Stopping nzbd while the schema is updated (it is started again in the next step)..."
    docker compose stop nzbd
  fi
  # The schema is applied by the one-shot setup service, the only container holding the owner role's secret.
  docker compose --profile setup run --rm setup || die "the schema could not be applied (see above; docs/RUNBOOK.md)."
  ok "schema applied (nzbd db migrate, owner role, setup service)"
else
  ok "SQLite: nzbd creates $DATA/nzbd.sqlite at its first start"
fi

# ---- 7. start -------------------------------------------------------------------------------------
step "7/9 Starting"
docker compose up -d
say "Waiting for nzbd to become healthy (up to 5 minutes)..."
cid=$(docker compose ps -q nzbd)
status=starting
for _ in $(seq 1 100); do
  status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)
  [ "$status" = healthy ] && break
  sleep 3
done
[ "$status" = healthy ] || die "nzbd is '$status'. See: docker compose logs nzbd   (docs/RUNBOOK.md, Troubleshooting)"
ok "nzbd is healthy"

if [ "$MODE" = external ] && [ "$NETMODE" != join ]; then
  ok "nzbd is attached to network '$NETNAME'"
  if ! docker inspect -f '{{json .NetworkSettings.Networks}}' "$EXT_NAME" 2>/dev/null | grep -q "\"$NETNAME\""; then
    if yesno "Attach the running container '$EXT_NAME' to '$NETNAME' now? (lost when it is recreated; use the snippet below)" y; then
      if [ -n "$TIP" ] && docker network connect --ip "$TIP" "$NETNAME" "$EXT_NAME" 2>/dev/null; then ok "'$EXT_NAME' attached as $TIP"
      elif docker network connect "$NETNAME" "$EXT_NAME" 2>/dev/null; then ok "'$EXT_NAME' attached"
      else warn "could not attach '$EXT_NAME'; docker network connect $NETNAME $EXT_NAME"; fi
    fi
  else
    ok "'$EXT_NAME' is already on '$NETNAME'"
  fi
  now=$(docker inspect -f '{{with index .NetworkSettings.Networks "'"$NETNAME"'"}}{{.IPAddress}}{{end}}' "$EXT_NAME" 2>/dev/null || true)
  if [ -n "$TIP" ] && [ -n "$now" ] && [ "$now" != "$TIP" ]; then
    warn "'$EXT_NAME' has the address $now on '$NETNAME', but nzbd trusts $TIP (NZBD_PROXY_TRUSTED_IP): pin the proxy to"
    warn "$TIP (snippet below) or fix the line in .env and re-run; until then nzbd sees every client as the proxy."
  fi
fi
if [ "$MODE" = external ] && [ "$NETMODE" = join ]; then
  # nzbd stays on the internal network (no egress); the existing proxy joins that network with the fixed address
  # nzbd trusts for X-Forwarded-For / X-Forwarded-Proto.
  if docker inspect -f '{{json .NetworkSettings.Networks}}' "$EXT_NAME" 2>/dev/null | grep -q '"nzbd_back"'; then
    ok "'$EXT_NAME' is already attached to nzbd_back"
  elif docker network connect --ip "$PROXY_IP" nzbd_back "$EXT_NAME" 2>/dev/null; then
    ok "'$EXT_NAME' attached to the internal network nzbd_back as $PROXY_IP"
  else
    warn "could not attach '$EXT_NAME' to nzbd_back at $PROXY_IP; do it by hand: docker network connect --ip $PROXY_IP nzbd_back $EXT_NAME"
  fi
fi

# ---- 8. root certificate (bundled proxy only) -----------------------------------------------------
step "8/9 Proxy root certificate"
CRT=nzbd-root.crt
if [ "$MODE" = external ]; then
  ok "skipped: TLS is handled by your own proxy"
else
  for _ in $(seq 1 30); do
    if docker run --rm -v "$VOLS_ABS/caddy:/d:ro" --entrypoint cat "$CADDY_IMG" /d/caddy/pki/authorities/local/root.crt >"$CRT" 2>/dev/null && [ -s "$CRT" ]; then break; fi
    rm -f "$CRT"; sleep 2
  done
  if [ -s "$CRT" ]; then ok "saved $PWD/$CRT (install it as a trusted root on the devices you browse from)"; else warn "root certificate not available yet; see docs/INSTALL.md step 6."; fi
fi

# ---- 9. user --------------------------------------------------------------------------------------
step "9/9 Your nzbd account"
if yesno "Create your nzbd user now? (asks for a password; prints a one-time MFA enrollment token)" y; then
  ask UNAME "User name" "owner"
  docker compose exec -it nzbd /nzbd user create "$UNAME"
else
  say "Later: docker compose exec -it nzbd /nzbd user create <name>"
fi

# ---- summary --------------------------------------------------------------------------------------
if [ "$MODE" = external ]; then
  say
  say "${c_g}${c_b}nzbd is running behind your proxy '$EXT_NAME'.${c_0}"
  say
  if [ "$NETMODE" = join ]; then
    PNET=nzbd_back; PIP=$PROXY_IP
    say "  1. Point your proxy at   http://nzbd:8080   (reachable on the Docker network nzbd_back)"
  else
    PNET=$NETNAME; PIP=$TIP
    say "  1. nzbd is on the network '$NETNAME' with the static address $APP_IP"
    say "     (upstream http://nzbd:8080 or http://$APP_IP:8080). Generated: $PWD/compose.yaml"
    if [ "$EXT_KIND" = traefik ]; then
      say "     Traefik labels were generated (deploy/compose.yaml): Host(\`$SITE\`) && !Path(\`/healthz\`), entrypoint ${TEP:-websecure},"
      say "     TLS$([ -n "$TRES" ] && echo ", resolver $TRES")$([ -n "$TOPT" ] && echo ", options $TOPT")$([ -n "$chain" ] && echo ", middlewares $chain");"
      say "     the docker provider must be enabled and able to see this network."
    fi
  fi
  say "  2. Make it persistent: add this to the compose file of '$EXT_NAME'"
  say "     (a live attach is lost when that container is recreated):"
  say
  say "       services:"
  say "         <your proxy service>:"
  say "           networks:"
  if [ -n "$PIP" ]; then
    say "             $PNET:"
    say "               ipv4_address: $PIP"
  else
    say "             - $PNET"
  fi
  say "       networks:"
  say "         $PNET:"
  say "           external: true"
  say
  [ -z "$PIP" ] || say "     (the fixed address is the one nzbd trusts for X-Forwarded-For / X-Forwarded-Proto)"
  say
  say "  3. Your proxy must: serve https://$SITE/, forward the Host header unchanged, set X-Forwarded-For (client address)"
  say "     and X-Forwarded-Proto https, accept 321 MiB bodies on /upload and 65 MiB on /api/v1/nzb, and (advised) answer 404"
  say "     for /healthz from outside. Idle upstream (keep-alive) connections must be dropped by the proxy"
  say "     within 8 s: nzbd closes them after 10 s, and a request sent on a closing connection fails with a 502"
  say "     (Caddy: transport http { keepalive 8s }; Traefik: forwardingTimeouts.idleConnTimeout 8s;"
  say "     nginx: no upstream keepalive by default)."
  say
  case "$EXT_KIND" in
    nginx)
      cat <<NGINX
  nginx:
       server {
         listen 443 ssl;  server_name $SITE;   # + your ssl_certificate lines
         client_max_body_size 65m;
         proxy_set_header Host \$http_host;
         proxy_set_header X-Forwarded-For \$remote_addr;
         proxy_set_header X-Forwarded-Proto \$scheme;
         location = /healthz { return 404; }
         location = /upload {
           client_max_body_size 321m;
           proxy_request_buffering off;   # stream to nzbd: no 321 MiB spool on the proxy's disk
           proxy_pass http://nzbd:8080;
         }
         location / {
           proxy_pass http://nzbd:8080;
         }
       }
NGINX
      ;;
    caddy)
      cat <<CADDY
  Caddy:
       $SITE {
         @h path /healthz
         respond @h 404
         @ui_upload path /upload
         request_body @ui_upload {
           max_size 321MiB
         }
         @other not path /upload
         request_body @other {
           max_size 65MiB
         }
         reverse_proxy nzbd:8080 {
           header_up X-Forwarded-For {remote_host}
           header_up X-Forwarded-Proto {scheme}
           transport http {
             keepalive 8s
           }
         }
       }
CADDY
      ;;
    traefik)
      [ "$NETMODE" = join ] && cat <<TRAEFIK
  Traefik (dynamic file configuration):
       http:
         routers:
           nzbd: { rule: "Host(\`$SITE\`) && !Path(\`/healthz\`)", entryPoints: [websecure], tls: {}, service: nzbd }
         services:
           nzbd: { loadBalancer: { servers: [ { url: "http://nzbd:8080" } ] } }
TRAEFIK
      ;;
    *) say "  (Any proxy works: upstream http://nzbd:8080 with the headers listed above.)" ;;
  esac
  say
  say "  NZBs:        drop .nzb files into $DATA_ABS/watch/  (or use the Upload page)"
  say "  Runs as:     $NZBD_UID:$NZBD_GID (owner of $DATA_ABS and $VOLS_ABS; NZBD_UID/NZBD_GID in .env)"
  say "  Settings:    $PWD/config/nzbd.toml (edit on the host, then: docker compose restart nzbd)"
  say "  Health:      docker compose exec nzbd /nzbd health"
  say "  Next:        docs/RUNBOOK.md (backups, restore, upgrade)"
  say
  # Header audit (D34): what the proxy's middlewares did to nzbd's security headers. Needs the site to resolve here and
  # the proxy to route it, so it is offered, not run.
  AUSER=$(get NZBD_TRAEFIK_AUTH_USERS); AUSER=${AUSER%%:*}
  hint=""
  if [ -z "$AUSER" ] && { [ -n "$(get NZBD_TRAEFIK_AUTH)" ] || [ "$EXT_KIND" != traefik ]; }; then hint=" [--user NAME]"; fi
  say "  Header audit: ./audit-headers.sh https://$SITE${AUSER:+ --user $AUSER}$hint"
  say "               (compares what your proxy delivers with nzbd's own headers; re-run it after changing middlewares)"
  if yesno "Run the header audit now? (https://$SITE must resolve here and be routed by your proxy)" n; then
    [ -z "$hint" ] || ask AUSER "User name of your proxy's outer login (blank = none)" ""
    case "$AUSER" in
      *[!A-Za-z0-9._@-]* | -*) warn "invalid user name; audit skipped." ;;
      *)
        set -- "https://$SITE"; [ -z "$AUSER" ] || set -- "$@" --user "$AUSER"
        sh ./audit-headers.sh "$@" || warn "the audit reported findings or could not fetch the page (see above)."
        ;;
    esac
  fi
  say
  exit 0
fi

url="https://$SITE"; [ "$PORT" = 443 ] || url="$url:$PORT"
cat <<EOF

${c_g}${c_b}nzbd is running.${c_0}

  Open:        $url/
  Runs as:     $NZBD_UID:$NZBD_GID (owner of $DATA_ABS and $VOLS_ABS; NZBD_UID/NZBD_GID in .env)
  Make sure:   '$SITE' resolves to $BIND on your devices (LAN DNS or a hosts entry)
  Trust:       $PWD/$CRT   (install as a trusted root certificate)
  Log in:      proxy user/password first, then your nzbd user + the one-time token, then scan the QR code
  NZBs:        drop .nzb files into $DATA_ABS/watch/  (or use the Upload page)
  Settings:    $PWD/config/nzbd.toml (edit on the host, then: docker compose restart nzbd)
  Health:      docker compose exec nzbd /nzbd health
  Next:        docs/RUNBOOK.md (backups, restore, upgrade)

EOF
