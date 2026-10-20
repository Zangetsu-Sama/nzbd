#!/bin/bash
# nzbd (T116): creates the two nzbd roles and the `nzbd` schema, then sets the role passwords from the generated secret
# files. Run ONCE by the postgres image's entrypoint (docker-entrypoint-initdb.d) on an empty data directory, as the
# superuser over the Unix socket (peer authentication). The passwords never appear on a command line or in the server
# log: psql reads them from the files into variables, and the statements are not logged (postgresql.conf).
# Re-running the role bootstrap on an existing server (it is idempotent): docs/RUNBOOK.md "PostgreSQL maintenance".
set -eu
su_psql() {
  PGHOST='' PGHOSTADDR='' psql -v ON_ERROR_STOP=1 --username postgres --no-password --no-psqlrc --dbname "$POSTGRES_DB" "$@"
}
for f in /etc/nzbd-pg/superuser/*.sql; do
  printf 'nzbd: running %s\n' "${f##*/}"
  su_psql --quiet -f "$f"
done
su_psql --quiet <<'SQL'
\set app `cat /run/pg-secrets/nzbd_db_password`
\set owner `cat /run/pg-secrets/nzbd_db_owner_password`
SET log_statement = 'none';
ALTER ROLE nzbd_app PASSWORD :'app';
ALTER ROLE nzbd_owner PASSWORD :'owner';
SQL
printf 'nzbd: roles nzbd_owner and nzbd_app are ready (passwords set from the secret files)\n'
