import { json, readBody, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";
import { decryptSecret } from "./_crypto.js";
import { validateGitUrl } from "./_scanner.js";
import { JOB_TYPES } from "./_jobs.js";

const HOST_PROVIDER = {
  "github.com": "GitHub",
  "www.github.com": "GitHub",
  "gitlab.com": "GitLab",
  "bitbucket.org": "Bitbucket"
};

async function hasToken(host, organizationId) {
  const provider = HOST_PROVIDER[host];
  if (!provider) return false;
  const cred = await repo.findConnectorCred(provider, organizationId);
  if (!cred?.accessToken) return false;
  try { decryptSecret(cred.accessToken); return true; } catch { return false; }
}

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
    if (!(await hasToken(meta.host, context.organization.id))) {
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
    json(res, 400, { error: error.message });
  }
}
