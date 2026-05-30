import { json, readBody, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";
import { decryptSecret } from "./_crypto.js";
import { runRepair } from "./_repair.js";
import { validateGitUrl } from "./_scanner.js";

const HOST_PROVIDER = {
  "github.com": "GitHub",
  "www.github.com": "GitHub",
  "gitlab.com": "GitLab",
  "bitbucket.org": "Bitbucket"
};

async function tokenFor(meta, organization) {
  const provider = HOST_PROVIDER[meta.host];
  if (!provider) return null;
  const cred = await repo.findConnectorCred(provider, organization.id);
  if (!cred?.accessToken) return null;
  try {
    return decryptSecret(cred.accessToken);
  } catch {
    return null;
  }
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

    const report = await repo.findReport(body.reportId, context.organization.id);
    if (!report) {
      json(res, 404, { error: "Scan report not found. Run a scan first, then approve repairs from that report." });
      return;
    }

    const selected = report.findings.filter((f) => findingIds.includes(f.id));
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

    const token = await tokenFor(meta, context.organization);

    let result;
    try {
      result = await runRepair({
        sourceUrl: report.sourceUrl,
        token,
        findings: selected,
        reportId: report.id
      });
    } catch (err) {
      const status = err.code === "access" || err.code === "unsupported" ? 422 : 502;
      json(res, status, { error: err.message || "Repair failed." });
      return;
    }

    if (!result.opened) {
      json(res, 200, {
        status: "no_changes",
        organization: context.organization.slug,
        reportId: report.id,
        reason: result.reason,
        manual: result.manual
      });
      return;
    }

    json(res, 200, {
      status: "pull_request_opened",
      organization: context.organization.slug,
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
    });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
