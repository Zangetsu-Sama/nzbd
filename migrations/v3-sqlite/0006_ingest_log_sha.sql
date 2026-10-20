-- v3-sqlite/0006_ingest_log_sha.sql. Forward-only.
-- Same index as Postgres `migrations/v3/0004_ops.sql` (`ingest_log_failed_sha`): the per-file failure count
-- read on every ingest failure (`count_failed_for_sha`) was a full scan of the log.
CREATE INDEX ingest_log_failed_sha ON ingest_log(sha256) WHERE outcome = 'failed';
