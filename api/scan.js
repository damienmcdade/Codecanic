import { json, planFor, readBody, resolveOrgContext, ClientError } from "./_lib.js";
import * as repo from "./_repo.js";
import { validateGitUrl } from "./_scanner.js";
import { JOB_TYPES } from "./_jobs.js";
import { logger } from "./_log.js";

// Per-org enqueue rate limit (fixed window). Clone+scan+OSV+PR are expensive, so
// cap the burst an org can queue per hour. Tunable via env.
const SCAN_RATE_LIMIT = Number(process.env.CODECANIC_SCAN_RATE_LIMIT || 20);
const SCAN_RATE_WINDOW_MS = Number(process.env.CODECANIC_SCAN_RATE_WINDOW_MS || 60 * 60 * 1000);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  try {
    const context = await resolveOrgContext(req);
    if (!context.authenticated) {
      json(res, 401, { error: "Sign in to start a scan." });
      return;
    }
    if (!context.organization) {
      json(res, 400, { error: "Create or select an organization before scanning." });
      return;
    }
    if (!context.user.emailVerified) {
      json(res, 403, { error: "Verify your email address before scanning.", code: "email_unverified" });
      return;
    }

    const body = await readBody(req);
    if (!body.sourceUrl) {
      json(res, 400, { error: "Provide a repository URL to scan (https://host/owner/repo)." });
      return;
    }
    // Validate the URL up front so a bad URL is a clean 400, not a failed job.
    try {
      validateGitUrl(body.sourceUrl);
    } catch (err) {
      json(res, 400, { error: err.message });
      return;
    }

    // Per-org enqueue rate limit (abuse / DoS bound, independent of the plan's
    // monthly quota). Surfaces as a 429 with Retry-After.
    const allowed = await repo.checkRateLimit(`scan:${context.organization.id}`, SCAN_RATE_LIMIT, SCAN_RATE_WINDOW_MS);
    if (!allowed) {
      res.setHeader("Retry-After", String(Math.ceil(SCAN_RATE_WINDOW_MS / 1000)));
      throw new ClientError(`Too many scans queued. Limit is ${SCAN_RATE_LIMIT} per hour for this organization. Try again later.`, 429);
    }

    // Free-plan monthly scan limit (Pro is unlimited + ad-free).
    const plan = planFor(context.organization.plan);
    if (plan.monthlyScanLimit != null) {
      const used = await repo.countScansThisMonth(context.organization.id);
      if (used >= plan.monthlyScanLimit) {
        json(res, 402, {
          error: `Monthly scan limit reached (${plan.monthlyScanLimit}). Upgrade to Pro for unlimited scans.`,
          code: "scan_limit", limit: plan.monthlyScanLimit, used
        });
        return;
      }
    }

    // Enqueue the (slow) clone+scan work; the worker runs it and stores a report.
    const job = await repo.enqueueJob({
      type: JOB_TYPES.SCAN,
      organizationId: context.organization.id,
      userId: context.user.id,
      payload: {
        sourceUrl: body.sourceUrl,
        scanDepth: body.scanDepth || "full",
        tier: body.tier || context.organization.plan || "Free",
        organizationId: context.organization.id,
        organizationSlug: context.organization.slug,
        organizationPlan: context.organization.plan
      }
    });

    json(res, 202, { jobId: job.id, type: "scan", status: job.status, pollUrl: `/api/jobs/${job.id}` });
  } catch (error) {
    const expose = error?.expose === true;
    const statusCode = expose ? error.statusCode || 400 : 500;
    if (!expose) logger.error("scan.handler_error", { err: error });
    json(res, statusCode, { error: expose ? error.message : "Request failed." });
  }
}
