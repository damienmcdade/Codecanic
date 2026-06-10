import { json, readBody, resolveOrgContext, ClientError } from "./_lib.js";
import * as repo from "./_repo.js";
import { validateGitUrl } from "./_scanner.js";
import { hasConnection } from "./_github.js";
import { JOB_TYPES } from "./_jobs.js";
import { logger } from "./_log.js";

// Per-org enqueue rate limit (fixed window) — repair clones + pushes + opens PRs.
const REPAIR_RATE_LIMIT = Number(process.env.CODECANIC_REPAIR_RATE_LIMIT || 20);
const REPAIR_RATE_WINDOW_MS = Number(process.env.CODECANIC_REPAIR_RATE_WINDOW_MS || 60 * 60 * 1000);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  try {
    const context = await resolveOrgContext(req);
    if (!context.authenticated) {
      json(res, 401, { error: "Sign in to approve repairs." });
      return;
    }
    if (!context.organization) {
      json(res, 400, { error: "Create or select an organization before approving repairs." });
      return;
    }
    if (!context.user.emailVerified) {
      json(res, 403, { error: "Verify your email address before approving repairs.", code: "email_unverified" });
      return;
    }

    // Per-org enqueue rate limit (abuse / DoS bound).
    const allowed = await repo.checkRateLimit(`repair:${context.organization.id}`, REPAIR_RATE_LIMIT, REPAIR_RATE_WINDOW_MS);
    if (!allowed) {
      res.setHeader("Retry-After", String(Math.ceil(REPAIR_RATE_WINDOW_MS / 1000)));
      throw new ClientError(`Too many repairs queued. Limit is ${REPAIR_RATE_LIMIT} per hour for this organization. Try again later.`, 429);
    }

    const body = await readBody(req);
    const findingIds = Array.isArray(body.findingIds) ? body.findingIds : [];
    if (!findingIds.length) {
      json(res, 400, { error: "At least one finding must be selected." });
      return;
    }
    if (!body.reportId) {
      json(res, 400, { error: "A reportId from a prior scan is required to repair." });
      return;
    }

    // Fast, synchronous validation — keep clear error codes before queueing.
    const report = await repo.findReport(body.reportId, context.organization.id);
    if (!report) {
      json(res, 404, { error: "Scan report not found. Run a scan first, then approve repairs from that report." });
      return;
    }
    const selected = (report.findings || []).filter((f) => findingIds.includes(f.id));
    if (!selected.length) {
      json(res, 400, { error: "None of the selected findings exist in that report." });
      return;
    }
    let meta;
    try {
      meta = validateGitUrl(report.sourceUrl);
    } catch (err) {
      json(res, 400, { error: `Report source is not repairable: ${err.message}` });
      return;
    }
    if (!meta.host.endsWith("github.com")) {
      json(res, 422, { error: "Automated pull requests are supported for GitHub repositories in v1." });
      return;
    }
    if (!(await hasConnection(meta.host, context.organization.id))) {
      json(res, 422, { error: "Connect GitHub with write access for this organization to open repair pull requests." });
      return;
    }

    // Enqueue the (slow) clone+patch+push+PR work.
    const job = await repo.enqueueJob({
      type: JOB_TYPES.REPAIR,
      organizationId: context.organization.id,
      userId: context.user.id,
      payload: { reportId: report.id, findingIds, organizationId: context.organization.id }
    });

    json(res, 202, { jobId: job.id, type: "repair", status: job.status, pollUrl: `/api/jobs/${job.id}` });
  } catch (error) {
    const expose = error?.expose === true;
    const statusCode = expose ? error.statusCode || 400 : 500;
    if (!expose) logger.error("repair.handler_error", { err: error });
    json(res, statusCode, { error: expose ? error.message : "Request failed." });
  }
}
