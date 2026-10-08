//! Transfer queue: folder expansion, a concurrency limit, conflict decisions,
//! pause/resume/cancel/retry, checksum verification and automatic resumption
//! after a reconnect.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::{AppError, Manager, UiEvent};
use crate::sftp::transfer::{self, Control, Direction, PART_SUFFIX};
use crate::sftp::{SftpError, remote_join};
use crate::validate;

const MAX_RUNNING: usize = 3;
const PROGRESS_EVERY_MS: u128 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    Queued,
    Running,
    Paused,
    /// Waiting for the user: the destination already exists.
    Conflict,
    Done,
    Skipped,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictChoice {
    Overwrite,
    Skip,
    KeepBoth,
}

struct Job {
    id: u64,
    session: String,
    direction: Direction,
    local: PathBuf,
    remote: String,
    name: String,
    size: u64,
    done: u64,
    state: JobState,
    error: Option<String>,
    verified: Option<bool>,
    control: Arc<Control>,
    batch: u64,
    choice: Option<ConflictChoice>,
    /// Failed because the connection dropped: resumes automatically on reconnect.
    interrupted: bool,
    speed: f64,
    last_tick: Option<(Instant, u64)>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    pub id: u64,
    pub session: String,
    pub direction: Direction,
    pub name: String,
    pub local: String,
    pub remote: String,
    pub size: u64,
    pub done: u64,
    pub state: JobState,
    pub error: Option<String>,
    pub verified: Option<bool>,
    pub bytes_per_sec: u64,
}

#[derive(Default)]
struct Inner {
    jobs: Vec<Job>,
    batch_choice: HashMap<u64, ConflictChoice>,
}

#[derive(Default)]
pub struct Queue {
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    last_emit: Mutex<Option<Instant>>,
}

impl Queue {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> Option<T> {
        self.inner.lock().ok().map(|mut i| f(&mut i))
    }

    fn job<T>(&self, id: u64, f: impl FnOnce(&mut Job) -> T) -> Option<T> {
        self.with(|i| i.jobs.iter_mut().find(|j| j.id == id).map(f)).flatten()
    }

    pub fn snapshot(&self) -> Vec<JobView> {
        self.with(|i| {
            i.jobs
                .iter()
                .map(|j| JobView {
                    id: j.id,
                    session: j.session.clone(),
                    direction: j.direction,
                    name: j.name.clone(),
                    local: j.local.to_string_lossy().into_owned(),
                    remote: j.remote.clone(),
                    size: j.size,
                    done: j.done,
                    state: j.state,
                    error: j.error.clone(),
                    verified: j.verified,
                    bytes_per_sec: j.speed as u64,
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn emit(&self, m: &Manager, force: bool) {
        let now = Instant::now();
        if let Ok(mut last) = self.last_emit.lock() {
            if !force && last.is_some_and(|t| now.duration_since(t).as_millis() < PROGRESS_EVERY_MS) {
                return;
            }
            *last = Some(now);
        }
        m.emit(UiEvent::Transfers { jobs: self.snapshot() });
    }

    fn push(&self, session: &str, direction: Direction, local: PathBuf, remote: String, size: u64, batch: u64) {
        let name = match direction {
            Direction::Upload => local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            Direction::Download => remote.rsplit('/').next().unwrap_or_default().to_owned(),
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.with(|i| {
            i.jobs.push(Job {
                id,
                session: session.into(),
                direction,
                local,
                remote,
                name,
                size,
                done: 0,
                state: JobState::Queued,
                error: None,
                verified: None,
                control: Arc::default(),
                batch,
                choice: None,
                interrupted: false,
                speed: 0.0,
                last_tick: None,
            })
        });
    }

    /// Queues local files and folders for upload into `remote_dir`.
    pub async fn enqueue_upload(&self, m: &Arc<Manager>, session: &str, locals: Vec<PathBuf>, remote_dir: String) -> Result<(), AppError> {
        let fs = m.sftp(session).await?;
        let batch = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        for local in locals {
            let name =
                local.file_name().map(|n| n.to_string_lossy().into_owned()).ok_or_else(|| AppError::Invalid("Invalid file.".into()))?;
            let meta = std::fs::symlink_metadata(&local)?;
            let target = remote_join(&remote_dir, &name);
            if meta.is_dir() {
                let _ = fs.mkdir(&target).await;
                let tree = tokio::task::spawn_blocking({
                    let local = local.clone();
                    move || transfer::walk_local(&local)
                })
                .await
                .map_err(|e| AppError::Invalid(e.to_string()))??;
                for (path, rel, is_dir) in tree {
                    let remote = transfer::remote_under(&target, &rel);
                    if is_dir {
                        let _ = fs.mkdir(&remote).await;
                    } else {
                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        self.push(session, Direction::Upload, path, remote, size, batch);
                    }
                }
            } else if meta.is_file() {
                self.push(session, Direction::Upload, local, target, meta.len(), batch);
            }
        }
        self.emit(m, true);
        self.pump(m);
        Ok(())
    }

    /// Queues remote files and folders for download into `local_dir`. Remote
    /// names are validated per component, so a hostile listing can't escape it.
    pub async fn enqueue_download(
        &self,
        m: &Arc<Manager>,
        session: &str,
        remotes: Vec<String>,
        local_dir: PathBuf,
    ) -> Result<(), AppError> {
        if crate::sftp::is_app_private(&local_dir, &m.engine.paths) {
            return Err(AppError::Invalid("Choose a folder outside Simple Connect's private data.".into()));
        }
        let fs = m.sftp(session).await?;
        let batch = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        for remote in remotes {
            let entry = fs.stat(&remote).await?;
            let root = validate::join_local(&local_dir, &entry.name).map_err(|e| AppError::Invalid(e.to_string()))?;
            if entry.kind == crate::sftp::EntryKind::Dir {
                std::fs::create_dir_all(&root)?;
                for (path, rel, is_dir) in transfer::walk_remote(&fs, &remote).await? {
                    let local = transfer::local_under(&root, &rel).map_err(|e| AppError::Invalid(e.to_string()))?;
                    if is_dir {
                        std::fs::create_dir_all(&local)?;
                    } else {
                        let size = fs.stat(&path).await.map(|e| e.size).unwrap_or(0);
                        self.push(session, Direction::Download, local, path, size, batch);
                    }
                }
            } else {
                self.push(session, Direction::Download, root, remote, entry.size, batch);
            }
        }
        self.emit(m, true);
        self.pump(m);
        Ok(())
    }

    /// Starts queued jobs up to the concurrency limit.
    fn pump(&self, m: &Arc<Manager>) {
        let start: Vec<u64> = self
            .with(|i| {
                let running = i.jobs.iter().filter(|j| j.state == JobState::Running).count();
                let ids: Vec<u64> =
                    i.jobs.iter().filter(|j| j.state == JobState::Queued).take(MAX_RUNNING.saturating_sub(running)).map(|j| j.id).collect();
                for j in i.jobs.iter_mut().filter(|j| ids.contains(&j.id)) {
                    j.state = JobState::Running;
                    j.error = None;
                    j.control = Arc::default();
                }
                ids
            })
            .unwrap_or_default();
        for id in start {
            tokio::spawn(run_job(m.clone(), id));
        }
    }

    fn finish(&self, m: &Arc<Manager>, id: u64, state: JobState, error: Option<String>) {
        self.job(id, |j| {
            j.state = state;
            j.error = error;
            j.speed = 0.0;
        });
        self.emit(m, true);
        self.pump(m);
    }

    pub fn pause(&self, m: &Arc<Manager>, id: u64) {
        self.job(id, |j| {
            if matches!(j.state, JobState::Running | JobState::Queued) {
                j.control.stop();
                j.state = JobState::Paused;
            }
        });
        self.emit(m, true);
    }

    pub fn resume(&self, m: &Arc<Manager>, id: u64) {
        self.job(id, |j| {
            if matches!(j.state, JobState::Paused | JobState::Failed) {
                j.state = JobState::Queued;
                j.interrupted = false;
            }
        });
        self.emit(m, true);
        self.pump(m);
    }

    pub fn cancel(&self, m: &Arc<Manager>, id: u64) {
        let target = self.job(id, |j| {
            j.control.stop();
            let was_running = j.state == JobState::Running;
            if !matches!(j.state, JobState::Done | JobState::Skipped) {
                j.state = JobState::Cancelled;
            }
            (was_running, j.direction, j.local.clone(), j.remote.clone(), j.session.clone())
        });
        // A running job removes its own partial file when it stops.
        if let Some((false, direction, local, remote, session)) = target {
            remove_part(m, direction, &local, &remote, &session);
        }
        self.emit(m, true);
    }

    pub fn resolve(&self, m: &Arc<Manager>, id: u64, choice: ConflictChoice, apply_to_all: bool) {
        self.with(|i| {
            let Some(j) = i.jobs.iter_mut().find(|j| j.id == id && j.state == JobState::Conflict) else { return };
            j.choice = Some(choice);
            j.state = JobState::Queued;
            let batch = j.batch;
            if apply_to_all {
                i.batch_choice.insert(batch, choice);
                for other in i.jobs.iter_mut().filter(|o| o.batch == batch && o.state == JobState::Conflict) {
                    other.choice = Some(choice);
                    other.state = JobState::Queued;
                }
            }
        });
        self.emit(m, true);
        self.pump(m);
    }

    pub fn clear_finished(&self, m: &Arc<Manager>) {
        self.with(|i| i.jobs.retain(|j| !matches!(j.state, JobState::Done | JobState::Skipped | JobState::Cancelled)));
        self.emit(m, true);
    }

    pub fn cancel_session(&self, session: &str) {
        self.with(|i| {
            for j in i.jobs.iter_mut().filter(|j| j.session == session) {
                j.control.stop();
                if !matches!(j.state, JobState::Done | JobState::Skipped) {
                    j.state = JobState::Cancelled;
                }
            }
        });
    }

    /// After a reconnect, re-queues jobs that failed because the link dropped.
    pub fn resume_interrupted(&self, m: &Arc<Manager>, session: &str) {
        let any = self
            .with(|i| {
                let mut any = false;
                for j in i.jobs.iter_mut().filter(|j| j.session == session && j.interrupted && j.state == JobState::Failed) {
                    j.state = JobState::Queued;
                    j.interrupted = false;
                    any = true;
                }
                any
            })
            .unwrap_or(false);
        if any {
            self.emit(m, true);
            self.pump(m);
        }
    }
}

fn remove_part(m: &Arc<Manager>, direction: Direction, local: &Path, remote: &str, session: &str) {
    match direction {
        Direction::Download => {
            let mut p = local.as_os_str().to_owned();
            p.push(PART_SUFFIX);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
        Direction::Upload => {
            let (m, part, session) = (m.clone(), format!("{remote}{PART_SUFFIX}"), session.to_owned());
            tokio::spawn(async move {
                if let Ok(fs) = m.sftp(&session).await {
                    let _ = fs.sftp.fs().remove_file(&part).await;
                }
            });
        }
    }
}

async fn run_job(m: Arc<Manager>, id: u64) {
    let q = &m.transfers;
    let Some((session, direction, mut local, mut remote, control, choice)) = q
        .with(|i| {
            let j = i.jobs.iter().find(|j| j.id == id)?;
            let choice = j.choice.or_else(|| i.batch_choice.get(&j.batch).copied());
            Some((j.session.clone(), j.direction, j.local.clone(), j.remote.clone(), j.control.clone(), choice))
        })
        .flatten()
    else {
        return;
    };

    let fs = match m.sftp(&session).await {
        Ok(fs) => fs,
        Err(e) => {
            q.job(id, |j| j.interrupted = true);
            return q.finish(&m, id, JobState::Failed, Some(e.to_string()));
        }
    };

    // Destination already exists → ask (or apply the chosen policy).
    let exists = match direction {
        Direction::Upload => fs.exists(&remote).await,
        Direction::Download => local.symlink_metadata().is_ok(),
    };
    let mut overwrite = false;
    if exists {
        match choice {
            None => return q.finish(&m, id, JobState::Conflict, None),
            Some(ConflictChoice::Skip) => return q.finish(&m, id, JobState::Skipped, None),
            Some(ConflictChoice::Overwrite) => overwrite = true,
            Some(ConflictChoice::KeepBoth) => {
                let name = q.job(id, |j| j.name.clone()).unwrap_or_default();
                for n in 1..1000 {
                    let candidate = transfer::numbered(&name, n);
                    let free = match direction {
                        Direction::Upload => {
                            let r = remote_join(&crate::sftp::remote_parent(&remote), &candidate);
                            (!fs.exists(&r).await).then_some((None, Some(r)))
                        }
                        Direction::Download => {
                            let l = local.with_file_name(&candidate);
                            (l.symlink_metadata().is_err()).then_some((Some(l), None))
                        }
                    };
                    if let Some((l, r)) = free {
                        if let Some(l) = l {
                            local = l;
                        }
                        if let Some(r) = r {
                            remote = r;
                        }
                        q.job(id, |j| {
                            j.local = local.clone();
                            j.remote = remote.clone();
                            j.name = candidate;
                        });
                        break;
                    }
                }
            }
        }
    }

    let progress = |done: u64, total: u64| {
        q.job(id, |j| {
            let now = Instant::now();
            if let Some((t, d)) = j.last_tick {
                let dt = now.duration_since(t).as_secs_f64();
                if dt > 0.2 {
                    let rate = done.saturating_sub(d) as f64 / dt;
                    j.speed = if j.speed == 0.0 { rate } else { j.speed * 0.7 + rate * 0.3 };
                    j.last_tick = Some((now, done));
                }
            } else {
                j.last_tick = Some((now, done));
            }
            j.done = done;
            j.size = total;
        });
        q.emit(&m, false);
    };

    let result = match direction {
        Direction::Upload => transfer::upload(&fs, &local, &remote, overwrite, &control, progress).await,
        Direction::Download => transfer::download(&fs, &remote, &local, &control, progress).await,
    };

    match result {
        Ok(outcome) => {
            let mut verified = None;
            if m.settings().verify_checksums
                && let Ok(s) = m.session(&session)
                && let Some(master) = s.master()
            {
                verified = transfer::remote_sha256(&m.engine.ossh, &master, &s.req.dest, &remote).await.map(|d| d == outcome.sha256);
            }
            q.job(id, |j| j.verified = verified);
            if verified == Some(false) {
                q.finish(&m, id, JobState::Failed, Some("The checksums don't match. The copy may be damaged; retry the transfer.".into()));
            } else {
                q.finish(&m, id, JobState::Done, None);
            }
        }
        Err(SftpError::Cancelled) => {
            if q.job(id, |j| j.state) == Some(JobState::Cancelled) {
                remove_part(&m, direction, &local, &remote, &session);
            }
            q.emit(&m, true);
            q.pump(&m);
        }
        Err(e) => {
            let lost = m.session(&session).ok().and_then(|s| s.master()).is_none();
            if lost {
                m.reset_sftp(&session).await;
                q.job(id, |j| j.interrupted = true);
            }
            let msg = if lost { "The connection was lost. The transfer resumes after reconnecting.".to_owned() } else { e.to_string() };
            q.finish(&m, id, JobState::Failed, Some(msg));
        }
    }
}
