// Proves the background job queue: enqueue → claim (exactly once) → complete/
// fail, org-scoped reads, stale-job requeue, and the worker's executor error
// handling. The full success path (scan a real repo) runs live in the e2e.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

const dir = await mkdtemp(join(tmpdir(), "codecanic-queue-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "queue-test-secret-0123456789abc";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const repo = await import("../api/_repo.js");
const { drainOnce } = await import("../api/_worker.js");
const { closeDb } = await import("../api/_db.js");

const owner = {
  id: randomUUID(), email: "q@codecanic.local", name: "q", passwordHash: "x",
  createdAt: new Date().toISOString(), termsAcceptedAt: new Date().toISOString(),
  privacyAcceptedAt: new Date().toISOString(), marketingOptIn: false, ageConfirmed: true, emailVerified: true
};

try {
  const { organization: org } = await repo.createUserWithOrg(owner, "q-org", "Q Org");
  const otherOrg = await repo.createOrganizationForUser("Other", "other", owner.id);

  console.log("Enqueue + claim (exactly once)");
  const enq = await repo.enqueueJob({ type: "scan", organizationId: org.id, userId: owner.id, payload: { sourceUrl: "https://github.com/o/r" } });
  ok("enqueue returns a queued job id", !!enq.id && enq.status === "queued");
  ok("getJob returns the queued job", (await repo.getJob(enq.id, org.id))?.status === "queued");

  const claimed = await repo.claimNextJob();
  ok("claim returns the job, marked running", claimed?.id === enq.id && claimed.status === "running");
  ok("claimed job has attempts=1", (await repo.getJob(enq.id, org.id))?.attempts === 1);
  ok("second claim returns null (no double-processing)", (await repo.claimNextJob()) === null);

  console.log("\nComplete / fail");
  await repo.completeJob(enq.id, { ok: true, n: 42 });
  const done = await repo.getJob(enq.id, org.id);
  ok("completeJob sets succeeded + result", done.status === "succeeded" && done.result?.n === 42);

  // failJob re-queues transient failures until MAX_JOB_ATTEMPTS is reached, then
  // marks the job permanently failed. (attempts is bumped by claimNextJob.)
  const enq2 = await repo.enqueueJob({ type: "scan", organizationId: org.id, payload: {} });
  await repo.claimNextJob();              // attempts = 1
  await repo.failJob(enq2.id, "boom");
  const retry1 = await repo.getJob(enq2.id, org.id);
  ok("failJob re-queues a transient failure", retry1.status === "queued" && /boom/.test(retry1.error));
  for (let i = 1; i < repo.MAX_JOB_ATTEMPTS; i++) {
    await repo.claimNextJob();           // attempts = 2 ... MAX
    await repo.failJob(enq2.id, "boom");
  }
  const failed = await repo.getJob(enq2.id, org.id);
  ok("failJob sets failed + error after retries exhausted", failed.status === "failed" && /boom/.test(failed.error));

  console.log("\nOrg scoping (no cross-tenant reads)");
  ok("getJob is org-scoped", (await repo.getJob(enq.id, otherOrg.id)) == null);
  ok("recentJobs lists this org's jobs", (await repo.recentJobs(org.id)).length >= 2);
  ok("recentJobs excludes other org", (await repo.recentJobs(otherOrg.id)).length === 0);

  console.log("\nStale-job requeue (crash recovery)");
  const enq3 = await repo.enqueueJob({ type: "scan", organizationId: org.id, payload: {} });
  await repo.claimNextJob(); // now 'running'
  const requeued = await repo.requeueStaleJobs(-1000); // cutoff in the near future → any running job is "stale"
  ok("stale running job is requeued", requeued >= 1 && (await repo.getJob(enq3.id, org.id)).status === "queued");

  console.log("\nWorker executor error handling");
  // Drain remaining queued jobs (enq3 + an unknown-type job). Their executors
  // throw (bad/missing URL, unknown type) → the worker must mark them failed.
  const badType = await repo.enqueueJob({ type: "bogus", organizationId: org.id, payload: {} });
  const processed = await drainOnce(10);
  ok("worker processed the remaining jobs", processed >= 2, `processed=${processed}`);
  ok("unknown-type job ends failed (not stuck running)", (await repo.getJob(badType.id, org.id)).status === "failed");
  ok("no jobs left queued/running after drain", (await repo.recentJobs(org.id)).every((j) => j.status === "succeeded" || j.status === "failed"));

  console.log("\nSuppressions (noise control)");
  await repo.addSuppression({ organizationId: org.id, fingerprint: "sast:js-eval:app.js", reason: "false positive", createdBy: owner.id });
  await repo.addSuppression({ organizationId: org.id, fingerprint: "hygiene:no-ci", createdBy: owner.id });
  let supp = await repo.suppressedFingerprints(org.id);
  ok("suppressed fingerprints returned as a set", supp.has("sast:js-eval:app.js") && supp.has("hygiene:no-ci"));
  ok("suppression list carries the reason", (await repo.listSuppressions(org.id)).some((s) => s.reason === "false positive"));
  ok("suppressions are org-scoped", (await repo.suppressedFingerprints(otherOrg.id)).size === 0);
  ok("re-suppressing is idempotent (unique)", await repo.addSuppression({ organizationId: org.id, fingerprint: "hygiene:no-ci", createdBy: owner.id }).then(() => true).catch(() => false));
  await repo.removeSuppression(org.id, "hygiene:no-ci");
  supp = await repo.suppressedFingerprints(org.id);
  ok("removeSuppression un-hides the finding", !supp.has("hygiene:no-ci") && supp.has("sast:js-eval:app.js"));
  // The scan executor hides suppressed findings: simulate its filter.
  const findings = [{ fingerprint: "sast:js-eval:app.js" }, { fingerprint: "dep:x" }];
  const visible = findings.filter((f) => !supp.has(f.fingerprint));
  ok("executor filter hides suppressed, keeps the rest", visible.length === 1 && visible[0].fingerprint === "dep:x");
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
