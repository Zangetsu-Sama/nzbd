//! The v3 search index in `nzbd` (T122; ARCHITECTURE v3 3.2-3.4): the single indexer task of `serve` and the
//! `nzbd search status|verify|rebuild` commands. The index is derived data in `search.index_dir`; the database (either
//! backend) stays the source of truth, read through the `IndexSource` adapter on [`Store`].
//!
//! Single writer: one `serve` per library is enforced by `paths.state/serve.lock` and, inside the index directory, by
//! Tantivy's own writer lock (a second indexer fails with `INDEXER_LOCKED` instead of corrupting the index).

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Subcommand;
use nzb_search::clock::SystemClock;
use nzb_search::engine::IndexDir;
use nzb_search::indexer::{Indexer, IndexerSettings};
use nzb_search::{SearchService, ServiceStatus, TantivyIndex};
use nzb_store::Store;
use nzb_store::prelude::*;

use crate::config::Config;

/// Live rounds per timer tick at most (each round reads up to `search.commit_max_docs` outbox rows): a burst is
/// drained in a few ticks without starving the stop signal.
const MAX_ROUNDS_PER_TICK: usize = 16;

/// What `serve` keeps: the engine for the web layer and the indexer task.
pub struct Running {
    /// The search engine the UI lists and searches through.
    pub index: TantivyIndex<Store>,
    /// The indexer task (ends with the stop signal).
    pub task: tokio::task::JoinHandle<()>,
}

/// Opens the index directory, starts the indexer (installs a servable generation or degrades and rebuilds) and spawns
/// its loop. Called by `serve` after the database is ready.
///
/// # Errors
/// The index directory cannot be opened, or another indexer holds it (`INDEXER_LOCKED`).
pub async fn start(
    cfg: &Config,
    store: &Store,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<Running, String> {
    let engine_cfg = cfg.search.engine();
    let tick = Duration::from_millis(engine_cfg.commit_interval_ms);
    let svc = SearchService::new(engine_cfg.clone(), Arc::new(SystemClock::new()));
    let dir = IndexDir::open(&cfg.index_dir())
        .map_err(|_| "search index directory: cannot open".to_owned())?;
    let mut indexer = Indexer::start(
        Arc::clone(&svc),
        store.clone(),
        dir,
        IndexerSettings::from_config(&engine_cfg),
    )
    .await
    .map_err(|e| format!("search index: {}", fixed(&e)))?;
    if let ServiceStatus::Degraded(reason) = svc.status() {
        tracing::warn!(
            reason,
            "search index not servable; degraded browse until the rebuild finishes"
        );
    }
    let source = store.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => break,
                () = tokio::time::sleep(tick) => {}
            }
            tick_once(&mut indexer, &source).await;
        }
    });
    Ok(Running {
        index: TantivyIndex::new(svc, store.clone()),
        task,
    })
}

/// One timer tick: a rebuild when the index needs one or the operator asked for it, otherwise live rounds until the
/// outbox is drained (bounded per tick). Errors are logged with fixed text and retried on the next tick; the indexer
/// never exits the process (review 32 I3).
async fn tick_once(indexer: &mut Indexer<Store>, store: &Store) {
    let requested = store
        .search_source_state()
        .await
        .is_ok_and(|s| s.rebuild_requested);
    if indexer.rebuild_needed() || requested {
        match indexer.rebuild().await {
            Ok(g) => tracing::info!(generation = g, "search index rebuilt"),
            Err(e) => tracing::warn!(error = fixed(&e), "search index rebuild failed; retrying"),
        }
        return;
    }
    for _ in 0..MAX_ROUNDS_PER_TICK {
        match indexer.run_once().await {
            Ok(r) if r.rows == 0 => break,
            Ok(r) => {
                if r.quarantined > 0 {
                    tracing::warn!(
                        quarantined = r.quarantined,
                        "search index: releases quarantined"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = fixed(&e), "search index round failed; retrying");
                break;
            }
        }
    }
}

/// A search error as a fixed string (no query text, no data).
fn fixed(e: &nzb_search::SearchError) -> &'static str {
    use nzb_search::SearchError as E;
    match e {
        E::Engine(_) => "engine error",
        E::Deadline => "deadline",
        E::Busy => "busy",
        E::NotServable(why) | E::OutOfRange(why) => why,
        E::Store(_) => "database error",
        E::Io(_) => "index io error",
        E::WriterUnavailable => "writer unavailable",
        E::Task => "task failed",
    }
}

/// `nzbd search ...`
#[derive(Subcommand)]
pub enum SearchAction {
    /// Index state: epoch, generation, outbox backlog, quarantined releases. Read-only.
    Status,
    /// Compare the index with the database (every release present with its current version, nothing extra). Needs
    /// the index directory not to be written meanwhile; read-only.
    Verify,
    /// Ask the running `serve` to rebuild the index into a new generation (the old one keeps serving until the switch).
    Rebuild,
}

/// Runs `nzbd search ...`.
///
/// # Errors
/// Database or index errors (fixed text).
pub fn run(cfg: &Config, action: &SearchAction) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let store = crate::ops::open_db(cfg).await?;
        let res = match action {
            SearchAction::Status => status(cfg, &store).await,
            SearchAction::Verify => verify(cfg, &store).await,
            SearchAction::Rebuild => {
                store
                    .search_request_rebuild(crate::now_unix())
                    .await
                    .map_err(|e| format!("search rebuild: {e}"))?;
                println!(
                    "rebuild requested; the running `nzbd serve` starts it within one indexer tick"
                );
                Ok(ExitCode::SUCCESS)
            }
        };
        store.close().await;
        res
    })
}

async fn status(cfg: &Config, store: &Store) -> Result<ExitCode, String> {
    let st = store
        .search_source_state()
        .await
        .map_err(|e| format!("search status: {e}"))?;
    let backlog = store
        .search_outbox_read(10_001)
        .await
        .map_err(|e| format!("search status: {e}"))?
        .len();
    let quarantined = store
        .search_quarantined(1_000)
        .await
        .map_err(|e| format!("search status: {e}"))?;
    // Read-only: never creates or chmods the configured directory (review 39 L1).
    let dir = IndexDir::read_only(&cfg.index_dir());
    println!("backend: {}", store.backend());
    println!(
        "active generation: {}",
        dir.current()
            .map_or_else(|| "none".to_owned(), |g| g.to_string())
    );
    println!(
        "last finished rebuild: generation {}",
        st.finished_generation
    );
    println!(
        "outbox backlog: {}{}",
        backlog.min(10_000),
        if backlog > 10_000 { "+" } else { "" }
    );
    println!(
        "rebuild in progress: {}",
        if st.replay { "yes" } else { "no" }
    );
    println!(
        "rebuild requested: {}",
        if st.rebuild_requested { "yes" } else { "no" }
    );
    println!("quarantined releases: {}", quarantined.len());
    for id in quarantined.iter().take(20) {
        println!("  release {id}");
    }
    Ok(ExitCode::SUCCESS)
}

async fn verify(cfg: &Config, store: &Store) -> Result<ExitCode, String> {
    use nzb_search::engine::{Engine, WriterSettings, check_servable};
    let engine_cfg = cfg.search.engine();
    let dir = IndexDir::read_only(&cfg.index_dir());
    let Some(g) = dir.current() else {
        println!("index NOT servable: no active generation");
        return Ok(ExitCode::from(1));
    };
    // Opening a generation takes Tantivy's writer lock: with `serve` running this fails (stop it, or use `status`).
    let engine =
        Engine::open(&dir.generation(g), WriterSettings::steady(&engine_cfg)).map_err(|e| {
            format!(
                "search verify: {} (the index is in use; stop `nzbd serve` first)",
                fixed(&e)
            )
        })?;
    let st = store
        .search_source_state()
        .await
        .map_err(|e| format!("search verify: {e}"))?;
    if let Err(e) = check_servable(&engine.payload(), st.epoch, st.outbox_last_seq) {
        println!("index NOT servable: {}", fixed(&e));
        return Ok(ExitCode::from(1));
    }
    let have = engine
        .live_versions()
        .map_err(|e| format!("search verify: {}", fixed(&e)))?;
    let mut want = Vec::new();
    let mut after = 0_i64;
    loop {
        let rows = store
            .search_index_scan(after, 10_000, usize::MAX, 0)
            .await
            .map_err(|e| format!("search verify: {e}"))?;
        let Some(last) = rows.last().map(|r| r.release.id) else {
            break;
        };
        want.extend(rows.into_iter().map(|r| (r.release.id, r.version)));
        after = last;
    }
    let backlog = store
        .search_outbox_read(1)
        .await
        .map_err(|e| format!("search verify: {e}"))?
        .len();
    let have_set: std::collections::BTreeMap<i64, u64> = have.into_iter().collect();
    let want_set: std::collections::BTreeMap<i64, u64> = want.into_iter().collect();
    let missing = want_set
        .keys()
        .filter(|k| !have_set.contains_key(k))
        .count();
    let extra = have_set
        .keys()
        .filter(|k| !want_set.contains_key(k))
        .count();
    let stale = want_set
        .iter()
        .filter(|(k, v)| have_set.get(k).is_some_and(|h| h < v))
        .count();
    println!(
        "{} release(s) in the database, {} in the index: {missing} missing, {extra} extra, {stale} stale",
        want_set.len(),
        have_set.len()
    );
    if backlog > 0 {
        println!(
            "note: the outbox is not empty; differences may be index lag (run again, or check `search status`)"
        );
    }
    Ok(if missing == 0 && extra == 0 && stale == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
