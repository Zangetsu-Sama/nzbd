-- v3-sqlite/0005_release_nfo.sql (T140, D41; docs/v3/DATA_MODEL.md 3.2b). Forward-only, never edit after release.
-- The NFO uploaded with an NZB: its raw bytes, at most 256 KiB, one per release. Keyed by the NZB's SHA-256 rather than
-- `release.id` (no foreign key). Deleting the release hides its NFO (`trashed_at`, review 49 M1: a fresh upload of the
-- same NZB never shows it, and may replace it); restoring the trash entry shows it again (`restored_at`); purging the
-- trash entry deletes it, and the purge also sweeps a restored NFO whose NZB never came back within a day (L1). The bytes are display data only, decoded for the page by
-- `nzb_core::decode_nfo`. Same shape as Postgres `migrations/v3/0011_release_nfo.sql`. A 0.5 binary refuses a database
-- with this migration (unknown ledger version); rollback = restore the pre-upgrade backup.
CREATE TABLE release_nfo (
  sha256    BLOB    PRIMARY KEY CHECK (length(sha256) = 32),
  bytes     BLOB    NOT NULL CHECK (length(bytes) BETWEEN 1 AND 262144),
  added_at  INTEGER NOT NULL,
  added_by  INTEGER REFERENCES account(id),  -- from the session / key owner, never input
  trashed_at  INTEGER,                      -- set while the release is in the trash; NULL = shown
  restored_at INTEGER                       -- when its trash entry was last restored
) STRICT;
