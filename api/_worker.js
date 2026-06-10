// In-process background worker. Polls the jobs table, claims one job at a time
// (replica-safe via SELECT ... FOR UPDATE SKIP LOCKED in the repo), runs its
// executor, and records the result/error. No external queue/broker needed.
import { readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as repo from "./_repo.js";
import { executeJob } from "./_jobs.js";
import { logger } from "./_log.js";
import { captureException } from "./_observability.js";

const IDLE_POLL_MS = Number(process.env.CODECANIC_WORKER_POLL_MS || 1000);
// R2: comfortably above the worst-case scan wall-time (clone 60s + OSV batches +
// tree walk). Combined with the per-job heartbeat, the requeue sweep only
// resurrects jobs whose worker has genuinely gone quiet — not slow-but-alive ones.
const STALE_MS = Number(process.env.CODECANIC_WORKER_STALE_MS || 30 * 60 * 1000);
const HEARTBEAT_MS = Number(process.env.CODECANIC_WORKER_HEARTBEAT_MS || 30 * 1000);

let running = false;
let stopped = false;
let active = false; // true while a job is mid-flight
const activeJobIds = new Set(); // R2: jobs THIS instance is actively running

async function tick() {
  // Recover jobs orphaned by a crashed/restarted worker.
  try {
    const requeued = await repo.requeueStaleJobs(STALE_MS);
    if (requeued) logger.warn("worker.requeued_stale", { count: requeued });
  } catch (err) {
    logger.error("worker.requeue_failed", { err });
  }

  let job;
  try {
    job = await repo.claimNextJob();
  } catch (err) {
    logger.error("worker.claim_failed", { err });
    return false;
  }
  if (!job) return false;

  // In-process guard (R2): if this instance is somehow handed a job it is already
  // executing (e.g. its own stale-requeue raced the heartbeat), don't run it
  // twice — leave it 'running' for the active execution to finish.
  if (activeJobIds.has(job.id)) {
    logger.warn("worker.skip_self_reclaim", { jobId: job.id });
    return true;
  }

  active = true;
  activeJobIds.add(job.id); // in-process guard: never re-claim a job we're running
  const startedAt = Date.now();
  // R2: keep the job's heartbeat fresh so a legitimately-long scan isn't seen as
  // stale and requeued (which would cause concurrent double-execution).
  const heartbeat = setInterval(() => {
    repo.heartbeatJob(job.id).catch(() => {});
  }, HEARTBEAT_MS);
  heartbeat.unref?.();
  try {
    const result = await executeJob(job);
    await repo.completeJob(job.id, result);
    logger.info("worker.job_done", { jobId: job.id, type: job.type, status: "succeeded", durationMs: Date.now() - startedAt });
  } catch (err) {
    await repo.failJob(job.id, err?.message || String(err)).catch(() => {});
    logger.error("worker.job_failed", { jobId: job.id, type: job.type, err, durationMs: Date.now() - startedAt });
    captureException(err, { jobId: job.id, type: job.type });
  } finally {
    clearInterval(heartbeat);
    activeJobIds.delete(job.id);
    active = false;
  }
  return true;
}

// R6: best-effort sweep of orphaned clone dirs left by a hard kill (SIGKILL gives
// the `finally` rm() in the scanner/repair engine no chance to run). Removes
// codecanic-scan-* / codecanic-repair-* dirs older than the cutoff.
export async function sweepStaleTempDirs(maxAgeMs = Number(process.env.CODECANIC_TMP_MAX_AGE_MS || 6 * 60 * 60 * 1000)) {
  const base = process.env.CODECANIC_SCAN_TMP || tmpdir();
  let removed = 0;
  try {
    const entries = await readdir(base, { withFileTypes: true });
    const cutoff = Date.now() - maxAgeMs;
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (!/^codecanic-(scan|repair)-/.test(entry.name)) continue;
      const full = join(base, entry.name);
      try {
        const info = await stat(full);
        if (info.mtimeMs < cutoff) { await rm(full, { recursive: true, force: true }); removed++; }
      } catch { /* ignore individual dir errors */ }
    }
  } catch { /* tmpdir unreadable — best effort */ }
  if (removed) logger.info("worker.swept_temp_dirs", { removed });
  return removed;
}

async function loop() {
  while (!stopped) {
    let didWork = false;
    try {
      didWork = await tick();
    } catch (err) {
      logger.error("worker.tick_error", { err });
    }
    // Drain the queue fast when busy; back off to a poll interval when idle.
    if (!didWork) await new Promise((r) => setTimeout(r, IDLE_POLL_MS));
  }
}

export function startWorker() {
  if (running) return;
  running = true;
  stopped = false;
  logger.info("worker.start", {});
  // R6: clean up clone dirs orphaned by a prior hard kill before processing.
  sweepStaleTempDirs().catch(() => {});
  loop();
}

export function stopWorker() {
  stopped = true;
  running = false;
}

export function isJobActive() {
  return active;
}

// Run the queue to completion once (used by tests).
export async function drainOnce(max = 100) {
  let done = 0;
  while (done < max && (await tick())) done++;
  return done;
}
