// Job executors: the slow work that used to run inline in the scan/repair
// handlers now runs here, driven by the background worker. Each executor
// returns the same shape the synchronous endpoint used to return, so the
// client gets an identical report/result after polling.
import { randomUUID } from "node:crypto";
import * as repo from "./_repo.js";
import { scanRepository, validateGitUrl, summarizeFindings } from "./_scanner.js";
import { runRepair } from "./_repair.js";
import { resolveRepoToken } from "./_github.js";
import { planFor } from "./_lib.js";

export const JOB_TYPES = { SCAN: "scan", REPAIR: "repair" };

// Noise control: drop findings whose fingerprint the org has suppressed, and
// report how many were hidden. Pure + exported so it's unit-tested directly
// (rather than the test reimplementing the filter).
export function applySuppressions(findings, suppressed) {
  const visible = findings.filter((f) => !suppressed.has(f.fingerprint));
  return { visible, suppressedCount: findings.length - visible.length };
}

async function executeScan(payload) {
  const meta = validateGitUrl(payload.sourceUrl);
  const plan = planFor(payload.tier || payload.organizationPlan || "Free");
  const token = await resolveRepoToken(meta.host, payload.organizationId);
  const result = await scanRepository({ sourceUrl: payload.sourceUrl, token, scanDepth: payload.scanDepth || "full" });

  const suppressed = await repo.suppressedFingerprints(payload.organizationId);
  const { visible, suppressedCount } = applySuppressions(result.findings, suppressed);
  result.findings = visible;
  result.summary = { ...summarizeFindings(visible), suppressed: suppressedCount };

  const report = {
    id: randomUUID(),
    engine: "real-v1",
    status: "report_ready",
    tier: payload.tier || payload.organizationPlan || "Free",
    organization: payload.organizationSlug,
    queue: plan.label,
    workers: plan.workers,
    sourceUrl: result.repository?.url || payload.sourceUrl,
    repository: result.repository,
    scanDepth: payload.scanDepth || "full",
    createdAt: new Date().toISOString(),
    scanned: result.scanned,
    summary: result.summary,
    findings: result.findings
  };
  await repo.insertReport({
    id: report.id, organizationId: payload.organizationId, sourceUrl: report.sourceUrl,
    createdAt: report.createdAt, summary: report.summary, findings: report.findings
  });
  return report;
}

async function executeRepair(payload) {
  const report = await repo.findReport(payload.reportId, payload.organizationId);
  if (!report) throw new Error("Scan report not found.");
  const selected = (report.findings || []).filter((f) => payload.findingIds.includes(f.id));
  if (!selected.length) throw new Error("None of the selected findings exist in that report.");
  const meta = validateGitUrl(report.sourceUrl);
  const token = await resolveRepoToken(meta.host, payload.organizationId);
  const result = await runRepair({
    sourceUrl: report.sourceUrl,
    token,
    findings: selected,
    reportId: report.id,
    // AI-generated edits computed at request time on the user's own key.
    aiPatches: Array.isArray(payload.aiPatches) ? payload.aiPatches : [],
    aiHandledIds: Array.isArray(payload.aiHandledIds) ? payload.aiHandledIds : [],
    aiNotes: Array.isArray(payload.aiNotes) ? payload.aiNotes : [],
  });

  if (!result.opened) {
    return { status: "no_changes", reportId: report.id, reason: result.reason, manual: result.manual };
  }
  return {
    status: "pull_request_opened",
    reportId: report.id,
    pullRequestUrl: result.pullRequestUrl,
    pullRequestNumber: result.pullRequestNumber,
    branchName: result.branch,
    baseBranch: result.baseBranch,
    applied: result.applied,
    manual: result.manual,
    confidence: result.confidence,
    confidenceScore: result.confidenceScore,
    createdAt: new Date().toISOString()
  };
}

export async function executeJob(job) {
  if (job.type === JOB_TYPES.SCAN) return executeScan(job.payload);
  if (job.type === JOB_TYPES.REPAIR) return executeRepair(job.payload);
  throw new Error(`Unknown job type: ${job.type}`);
}
