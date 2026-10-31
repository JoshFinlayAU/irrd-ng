//! `MirrorScheduler` (`irrd/mirroring/scheduler.py`), with v4's processes
//! as tasks.
//!
//! Every `MIRROR_FREQUENCY` seconds the scheduler starts an import task for
//! each mirrored source whose timer has expired and that has no task
//! running, starting at most `MAX_SIMULTANEOUS_RUNS` sources per round, in
//! configuration order. A finished task is reaped every second, as v4's
//! `update_process_state()` does.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use store::Store;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::messages;
use crate::mirror::runner::{MirrorContext, run_mirror_update};
use crate::mirror::settings::MirrorSettings;

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.scheduler";

/// v4's `MAX_SIMULTANEOUS_RUNS`: sources started per round.
pub const MAX_SIMULTANEOUS_RUNS: usize = 1;

/// The import runner's name, as v4 names its process.
pub const IMPORT_RUNNER: &str = "RPSLMirrorImportUpdateRunner";

/// The scheduler's state.
#[derive(Debug)]
pub struct MirrorScheduler {
    store: Store,
    processes: HashMap<String, JoinHandle<()>>,
    last_started_time: HashMap<String, i64>,
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl MirrorScheduler {
    /// A scheduler writing to `store`.
    pub fn new(store: Store) -> MirrorScheduler {
        MirrorScheduler {
            store,
            processes: HashMap::new(),
            last_started_time: HashMap::new(),
        }
    }

    /// `run()`: start what is due.
    pub fn run(&mut self, settings: &Arc<MirrorSettings>) {
        if settings.readonly_standby {
            return;
        }
        // ROAImportRunner, RoutePreferenceUpdateRunner and
        // ScopeFilterUpdateRunner are scheduled here in v4; they arrive
        // with Phase 5.
        let mut sources_started = 0;
        for src in &settings.sources {
            if sources_started >= MAX_SIMULTANEOUS_RUNS {
                break;
            }
            let mut started_import = false;
            let started_export = false;
            if src.is_mirror() {
                let ctx = MirrorContext {
                    store: self.store.clone(),
                    settings: settings.clone(),
                };
                let name = src.name.clone();
                started_import = self.run_if_relevant(
                    Some(&src.name),
                    IMPORT_RUNNER,
                    src.import_timer,
                    false,
                    move || tokio::spawn(run_mirror_update(ctx, name)),
                );
            }
            // SourceExportRunner (export_destination) and NRTM4Server
            // (nrtm4_server_private_key) are scheduled here in v4; they
            // arrive with Phase 6.
            if started_import || started_export {
                sources_started += 1;
            }
        }
    }

    /// `run_if_relevant()`: start the runner if its timer expired and it
    /// is not running already. Returns whether it started.
    pub fn run_if_relevant(
        &mut self,
        source: Option<&str>,
        runner_name: &str,
        timer: i64,
        allow_multiple: bool,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> bool {
        let mut process_name = runner_name.to_owned();
        if let Some(s) = source {
            process_name.push('-');
            process_name.push_str(s);
        }
        let current_time = now();
        let last = self
            .last_started_time
            .get(&process_name)
            .copied()
            .unwrap_or(0);
        let has_expired = ((last + timer) as f64) < current_time;
        if !has_expired || (self.processes.contains_key(&process_name) && !allow_multiple) {
            return false;
        }
        tracing::debug!(target: LOG_TARGET, "{}", messages::started_scheduled_process(&process_name, source));
        let handle = start();
        self.processes.insert(process_name.clone(), handle);
        self.last_started_time
            .insert(process_name, current_time as i64);
        true
    }

    /// `update_process_state()`: forget finished tasks.
    pub fn update_process_state(&mut self) {
        self.processes.retain(|_, h| !h.is_finished());
    }

    /// Names of the tasks running.
    pub fn running(&self) -> Vec<String> {
        let mut v: Vec<String> = self.processes.keys().cloned().collect();
        v.sort();
        v
    }

    /// `terminate_children()`.
    pub fn terminate_children(&mut self) {
        tracing::info!(target: LOG_TARGET, "{}", messages::SCHEDULER_TERMINATING);
        for (_, h) in self.processes.drain() {
            h.abort();
        }
    }
}

/// v4's main loop for the scheduler: every second reap finished tasks,
/// and every `mirror_frequency` seconds (first at start) run the
/// scheduler, until `shutdown` turns true.
pub async fn run_scheduler(
    store: Store,
    settings: watch::Receiver<Arc<MirrorSettings>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut scheduler = MirrorScheduler::new(store);
    let mut sleeps = u64::MAX;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let current = settings.borrow().clone();
        scheduler.update_process_state();
        if sleeps >= current.mirror_frequency() {
            scheduler.run(&current);
            sleeps = 0;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = shutdown.changed() => {}
        }
        sleeps = sleeps.saturating_add(1);
    }
    scheduler.terminate_children();
}

#[cfg(test)]
mod tests {
    //! v4's `test_scheduler.py`, for the parts that apply.

    use super::*;
    use crate::mirror::settings::SourceMirrorSettings;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().expect("dir");
        let s = Store::open(
            &store::StoreOptions::new(dir.path()),
            store::StoreSettings::default(),
        )
        .expect("store");
        (dir, s)
    }

    fn source(name: &str, timer: i64) -> SourceMirrorSettings {
        SourceMirrorSettings {
            name: name.into(),
            import_source: Some(vec!["url".into()]),
            import_timer: timer,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn runs_import_once_while_running_and_reaps() {
        let (_d, st) = store();
        let mut s = MirrorScheduler::new(st);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let mut rx = Some(rx);
        let mut started = 0;
        for _ in 0..2 {
            let r = rx.take();
            if s.run_if_relevant(Some("TEST"), IMPORT_RUNNER, 0, false, || {
                tokio::spawn(async move {
                    if let Some(r) = r {
                        let _ = r.await;
                    }
                })
            }) {
                started += 1;
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        // The second round does not start it: it is still running.
        assert_eq!(started, 1);
        s.update_process_state();
        assert_eq!(s.running(), ["RPSLMirrorImportUpdateRunner-TEST"]);
        let _ = tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await;
        s.update_process_state();
        assert!(s.running().is_empty());
    }

    #[tokio::test]
    async fn limits_simultaneous_runs() {
        let (_d, st) = store();
        let mut s = MirrorScheduler::new(st);
        let settings = Arc::new(MirrorSettings {
            sources: (1..=4).map(|i| source(&format!("TEST{i}"), 0)).collect(),
            download_timeout: 1,
            ..Default::default()
        });
        s.run(&settings);
        assert_eq!(s.running().len(), MAX_SIMULTANEOUS_RUNS);
        s.terminate_children();
    }

    #[tokio::test]
    async fn import_ignores_timer_not_expired() {
        let (_d, st) = store();
        let mut s = MirrorScheduler::new(st);
        let mut count = 0;
        for _ in 0..2 {
            if s.run_if_relevant(Some("TEST"), IMPORT_RUNNER, 100, false, || {
                tokio::spawn(async {})
            }) {
                count += 1;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.update_process_state();
        }
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn standby_runs_nothing() {
        let (_d, st) = store();
        let mut s = MirrorScheduler::new(st);
        let settings = Arc::new(MirrorSettings {
            readonly_standby: true,
            sources: vec![source("TEST", 0)],
            ..Default::default()
        });
        s.run(&settings);
        assert!(s.running().is_empty());
    }
}
