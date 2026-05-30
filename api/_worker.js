// In-process background worker. Polls the jobs table, claims one job at a time
// (replica-safe via SELECT ... FOR UPDATE SKIP LOCKED in the repo), runs its
// executor, and records the result/error. No external queue/broker needed.
import * as repo from "./_repo.js";
import { executeJob } from "./_jobs.js";
import { logger } from "./_log.js";
import { captureException } from "./_observability.js";

const IDLE_POLL_MS = Number(process.env.CODECANIC_WORKER_POLL_MS || 1000);
const STALE_MS = Number(process.env.CODECANIC_WORKER_STALE_MS || 10 * 60 * 1000);

let running = false;
let stopped = false;
let active = false; // true while a job is mid-flight

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

  active = true;
  const startedAt = Date.now();
  try {
    const result = await executeJob(job);
    await repo.completeJob(job.id, result);
    logger.info("worker.job_done", { jobId: job.id, type: job.type, status: "succeeded", durationMs: Date.now() - startedAt });
  } catch (err) {
    await repo.failJob(job.id, err?.message || String(err)).catch(() => {});
    logger.error("worker.job_failed", { jobId: job.id, type: job.type, err, durationMs: Date.now() - startedAt });
    captureException(err, { jobId: job.id, type: job.type });
  } finally {
    active = false;
  }
  return true;
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
