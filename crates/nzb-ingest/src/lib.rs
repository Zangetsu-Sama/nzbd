//! `nzb-ingest` — watch-folder discovery (T030) and the ingest pipeline (T031).
#![forbid(unsafe_code)]

pub mod cleanup;
mod error;
pub mod failure;
mod fsops;
pub mod import;
pub mod pipeline;
pub mod recovery;
pub mod rules;
pub mod runner;
pub mod scanner;
mod sidecar;
mod timefmt;
pub mod watcher;

#[cfg(test)]
mod pipeline_tests;

pub use error::{Disposition, IngestError};
pub use failure::{
    EXPIRED_DIR, FailedEntry, Reason, RetentionReport, RetryReport, RetryTarget, apply_retention,
    is_failed_name, list_failed, read_reason, retry,
};
pub use import::{
    ImportError, ImportGuard, ImportLimits, ImportReport, SkipReason, check_root, import_dir,
};
pub use pipeline::{
    DEFAULT_GROUP_MAX_JOBS, DEFAULT_GROUP_WINDOW, DEFAULT_MAX_INFLIGHT_BYTES, DEFAULT_WRITER_HOLD,
    DuplicatesAction, ImportFile, IngestHandle, IngestOutcome, IngestSettings, Job, MAX_QUEUE_CAP,
    MAX_WORKERS, OutcomeKind, Payload, Pipeline, PipelineConfig, QUEUE_CAP, Stats, SystemWallClock,
    WallClock,
};
pub use recovery::{
    DEFAULT_GC_GRACE_SECS, GcPlan, MAX_TRASH_PER_START, RecoveryConfig, RecoveryReport,
    STAGING_PREFIX, StoreCheck, check_store, gc_orphans, gc_plan, recover, staging_name,
};
pub use rules::{
    DryRun, DryRunEntry, DryRunSettings, Effect, HintOrigin, MAX_RULES, RuleError, RuleSpec,
    WatchRule, WatchRules, dry_run,
};
pub use runner::{
    CycleReport, DepthProbe, Heartbeat, LagGate, MIN_SCAN_GAP, RunnerConfig, ScanExit,
    SharedScanner, run_scan_loop, run_scan_loop_gated, scan_cycle, scan_cycle_gated,
};
pub use scanner::{
    Candidate, Clock, FileId, OpenError, Scanner, ScannerConfig, SystemClock, open_regular,
};
pub use timefmt::utc_stamp;
pub use watcher::{WatchHandle, spawn_watcher};
