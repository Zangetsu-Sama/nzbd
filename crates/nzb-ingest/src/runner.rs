//! Scan loop: scanner + watcher wake-ups feeding the pipeline queue.
//!
//! Carry-forward rules from the scanner review: a [`Candidate`](crate::Candidate) lives inside
//! its [`Job`](crate::Job) until the source has been handled; afterwards the loop calls
//! `finish(path)` when the file is gone and `fail_backoff(path)` when it is still there (the
//! move/remove failed, or the failure is not quarantined) so nothing hot-loops. Scans are at
//! least [`MIN_SCAN_GAP`] apart no matter how many wake-ups arrive.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use nzb_store::prelude::*;

use tokio::task::JoinSet;

use crate::error::IngestError;
use crate::pipeline::{IngestHandle, Job, WallClock};
use crate::scanner::{Clock, Scanner, heartbeat_fresh};
use crate::watcher::WatchHandle;

/// Minimum time between two scans, regardless of wake-ups (event floods must not spin us).
pub const MIN_SCAN_GAP: Duration = Duration::from_secs(1);

/// Liveness of the scan loop for `/healthz` (200 only if fresh, `INGEST_SPEC` §Observability).
#[derive(Debug, Clone, Default)]
pub struct Heartbeat(Arc<AtomicI64>);

impl Heartbeat {
    /// A heartbeat that has never beaten.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed scan cycle at `now` (Unix seconds).
    pub fn beat(&self, now: i64) {
        self.0.store(now, Ordering::Relaxed);
    }

    /// Time of the last completed cycle, if any.
    #[must_use]
    pub fn last(&self) -> Option<i64> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    /// True while the last beat is younger than 3 x `scan_interval`.
    #[must_use]
    pub fn is_fresh(&self, now: i64, scan_interval: Duration) -> bool {
        heartbeat_fresh(
            self.last().and_then(|t| u64::try_from(t).ok()),
            u64::try_from(now).unwrap_or(0),
            scan_interval,
        )
    }
}

/// Loop settings (from `ingest.scan_interval_secs`).
#[derive(Debug, Clone, Copy)]
pub struct RunnerConfig {
    /// Periodic scan interval (events only make scans earlier).
    pub scan_interval: Duration,
    /// Upper bound of candidates taken per cycle.
    pub max_batch: usize,
}

/// What one cycle did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CycleReport {
    /// Candidates handed to the pipeline.
    pub submitted: usize,
    /// Files that were still present afterwards and are backed off.
    pub backed_off: usize,
    /// A submit returned `ShuttingDown`: the workers are gone (fatal unless we are stopping).
    pub workers_gone: bool,
    /// The search index lags too far behind: nothing was offered this cycle ([`LagGate`]).
    pub paused: bool,
}

/// What a [`LagGate`] asks: the outbox depth now (`None` = unknown, the gate keeps its state).
pub type DepthProbe =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> + Send + Sync>;

/// Pauses the watch-folder scanner while the search index is too far behind the database (ARCHITECTURE v3 3.2
/// "Lag and backpressure", SEC-092): no candidate is offered while the outbox depth is above `pause_at`, and offering
/// resumes once it is below half of it (hysteresis, so the scanner does not flap at the limit). Uploads are not
/// paused (they are rate limited); files simply wait in the watch folder, nothing is lost. `pause_at = 0` never
/// pauses.
#[derive(Clone)]
pub struct LagGate {
    probe: DepthProbe,
    pause_at: u64,
    paused: Arc<AtomicBool>,
}

impl std::fmt::Debug for LagGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LagGate")
            .field("pause_at", &self.pause_at)
            .field("paused", &self.is_paused())
            .finish_non_exhaustive()
    }
}

impl LagGate {
    /// A gate over any depth source (tests use a fixed one).
    #[must_use]
    pub fn new(pause_at: u64, probe: DepthProbe) -> Self {
        Self {
            probe,
            pause_at,
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The gate of `serve`: the outbox span of the library ([`nzb_store::OutboxLag::depth`]).
    #[must_use]
    pub fn for_store(store: nzb_store::Store, pause_at: u64) -> Self {
        Self::new(
            pause_at,
            Arc::new(move || {
                let s = store.clone();
                Box::pin(async move { s.search_outbox_lag().await.ok().map(|l| l.depth) })
            }),
        )
    }

    /// Whether the scanner is paused right now (metrics and health).
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Re-evaluates the depth and answers whether candidates may be offered.
    pub async fn admit(&self) -> bool {
        if self.pause_at == 0 {
            return true;
        }
        let was = self.is_paused();
        let Some(depth) = (self.probe)().await else {
            return !was;
        };
        let now = if was {
            // Round up: for a limit of one, an empty outbox must resume ingestion. For
            // odd limits this also implements the documented strict "below half" boundary.
            depth >= self.pause_at.div_ceil(2)
        } else {
            depth > self.pause_at
        };
        if now != was {
            self.paused.store(now, Ordering::SeqCst);
            if now {
                tracing::warn!(
                    depth,
                    limit = self.pause_at,
                    "search index lags behind; watch-folder scanning paused"
                );
            } else {
                tracing::info!(
                    depth,
                    "search index caught up; watch-folder scanning resumed"
                );
            }
        }
        !now
    }
}

/// Why [`run_scan_loop`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanExit {
    /// The shutdown future resolved.
    Shutdown,
    /// The ingest workers disappeared while we were not shutting down: ingestion is dead and
    /// the supervisor must treat this as fatal.
    WorkersGone,
}

/// The scanner shared between the blocking directory walk and the async bookkeeping.
pub type SharedScanner<C> = Arc<Mutex<Scanner<C>>>;

/// One scan + processing cycle. The directory walk runs on a blocking thread.
pub async fn scan_cycle<C: Clock + 'static>(
    scanner: &SharedScanner<C>,
    handle: &IngestHandle,
    max_batch: usize,
) -> CycleReport {
    scan_cycle_gated(scanner, handle, max_batch, None).await
}

/// [`scan_cycle`] behind a [`LagGate`]: a paused gate offers nothing (the files wait where they are).
pub async fn scan_cycle_gated<C: Clock + 'static>(
    scanner: &SharedScanner<C>,
    handle: &IngestHandle,
    max_batch: usize,
    gate: Option<&LagGate>,
) -> CycleReport {
    if let Some(g) = gate
        && !g.admit().await
    {
        return CycleReport {
            paused: true,
            ..CycleReport::default()
        };
    }
    // Backpressure: never offer more than the queue can take (`INGEST_SPEC` §Backpressure).
    let offer = handle.free_slots().min(max_batch);
    let sc = Arc::clone(scanner);
    let found = tokio::task::spawn_blocking(move || {
        sc.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .scan(offer)
    })
    .await
    .unwrap_or_default();
    let mut set = JoinSet::new();
    for candidate in found {
        let path: PathBuf = candidate.path.clone();
        let h = handle.clone();
        set.spawn(async move {
            let res = h.submit(Job::watch(candidate)).await;
            (path, res)
        });
    }
    let mut report = CycleReport::default();
    while let Some(joined) = set.join_next().await {
        let Ok((path, res)) = joined else { continue };
        if matches!(res, Err(IngestError::ShuttingDown)) {
            report.workers_gone = true;
            continue;
        }
        if matches!(res, Err(IngestError::QueueFull)) {
            // Never reached a worker: the candidate guard was dropped, a later scan re-offers.
            continue;
        }
        report.submitted = report.submitted.saturating_add(1);
        let mut sc = scanner.lock().unwrap_or_else(PoisonError::into_inner);
        if std::fs::symlink_metadata(&path).is_ok() {
            sc.fail_backoff(&path);
            report.backed_off = report.backed_off.saturating_add(1);
        } else {
            sc.finish(&path);
        }
    }
    report
}

/// Runs scan cycles until `shutdown` resolves. Waits for a watcher event or the periodic
/// interval between cycles, but never starts two scans less than [`MIN_SCAN_GAP`] apart.
pub async fn run_scan_loop<C: Clock + 'static>(
    scanner: SharedScanner<C>,
    handle: IngestHandle,
    wake: Arc<WatchHandle>,
    cfg: RunnerConfig,
    heartbeat: Heartbeat,
    clock: Arc<dyn WallClock>,
    shutdown: impl Future<Output = ()>,
) -> ScanExit {
    run_scan_loop_gated(scanner, handle, wake, cfg, heartbeat, clock, None, shutdown).await
}

/// [`run_scan_loop`] behind a [`LagGate`] (`serve`). A paused cycle still beats the heartbeat:
/// the loop is alive, it is waiting for the index.
#[allow(clippy::too_many_arguments)] // the loop's dependencies, passed once
pub async fn run_scan_loop_gated<C: Clock + 'static>(
    scanner: SharedScanner<C>,
    handle: IngestHandle,
    wake: Arc<WatchHandle>,
    cfg: RunnerConfig,
    heartbeat: Heartbeat,
    clock: Arc<dyn WallClock>,
    gate: Option<LagGate>,
    shutdown: impl Future<Output = ()>,
) -> ScanExit {
    tokio::pin!(shutdown);
    let interval = cfg.scan_interval.max(MIN_SCAN_GAP);
    loop {
        let started = tokio::time::Instant::now();
        let report = scan_cycle_gated(&scanner, &handle, cfg.max_batch, gate.as_ref()).await;
        if report.workers_gone {
            // Do not beat: /healthz must go unhealthy even if the supervisor misses this.
            tracing::error!("ingest workers are gone; stopping the scan loop");
            return ScanExit::WorkersGone;
        }
        heartbeat.beat(clock.now_unix());
        if report.submitted > 0 {
            tracing::info!(
                submitted = report.submitted,
                backed_off = report.backed_off,
                queue = handle.queue_len(),
                "scan cycle"
            );
        }
        // Wait for a wake-up or the interval, in slices so shutdown stays responsive.
        // An interval beyond Instant's range has no periodic deadline; watcher events
        // and shutdown still work through the same bounded waits.
        let deadline = started.checked_add(interval);
        let min_next = started + MIN_SCAN_GAP;
        loop {
            let now = tokio::time::Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                break;
            }
            let slice = deadline.map_or(Duration::from_millis(500), |deadline| {
                (deadline - now).min(Duration::from_millis(500))
            });
            // `wait` also works on a disabled handle (plain timeout; `poke` still wakes it).
            let w = Arc::clone(&wake);
            let signalled = tokio::select! {
                () = &mut shutdown => return ScanExit::Shutdown,
                r = tokio::task::spawn_blocking(move || w.wait(slice)) => r.unwrap_or(false),
            };
            if signalled {
                break;
            }
        }
        // Minimum gap, however many events arrived.
        tokio::select! {
            () = &mut shutdown => return ScanExit::Shutdown,
            () = tokio::time::sleep_until(min_next) => {}
        }
    }
}
