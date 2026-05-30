import { json, readBody, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";
import { validateGitUrl } from "./_scanner.js";
import { JOB_TYPES } from "./_jobs.js";

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
    json(res, 400, { error: error.message });
  }
}
