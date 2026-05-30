import { json, planFor, readBody, resolveOrgContext } from "./_lib.js";
import { read, write } from "./_data.js";
import { decryptSecret } from "./_crypto.js";
import { scanRepository, validateGitUrl } from "./_scanner.js";
import { randomUUID } from "node:crypto";

const MAX_REPORTS_PER_ORG = 20;

// Map a git host to the connector provider whose token can clone it.
const HOST_PROVIDER = {
  "github.com": "GitHub",
  "www.github.com": "GitHub",
  "gitlab.com": "GitLab",
  "bitbucket.org": "Bitbucket"
};

async function tokenForRepo(meta, organization) {
  const provider = HOST_PROVIDER[meta.host];
  if (!provider) return null;
  const state = await read();
  const cred = state.connectorCreds.find(
    (c) => c.provider === provider && c.organizationId === organization.id
  );
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
      json(res, 401, { error: "Sign in to start a scan." });
      return;
    }
    if (!context.organization) {
      json(res, 400, { error: "Create or select an organization before scanning." });
      return;
    }

    const body = await readBody(req);
    if (!body.sourceUrl) {
      json(res, 400, { error: "Provide a repository URL to scan (https://host/owner/repo)." });
      return;
    }

    // Validate up front so a bad URL is a clean 400, not a 5xx.
    let meta;
    try {
      meta = validateGitUrl(body.sourceUrl);
    } catch (err) {
      json(res, 400, { error: err.message });
      return;
    }

    const tier = body.tier || context.organization.plan || "Free";
    const plan = planFor(tier);
    const token = await tokenForRepo(meta, context.organization);

    let result;
    try {
      result = await scanRepository({
        sourceUrl: body.sourceUrl,
        token,
        scanDepth: body.scanDepth || "full"
      });
    } catch (err) {
      // Honest failure: surface why we could not scan instead of faking findings.
      const isAccess = /private|Could not access|Authentication|not found/i.test(err.message || "");
      json(res, isAccess ? 422 : 502, {
        error: err.message || "Scan failed.",
        hint: isAccess
          ? "Connect the matching provider for this organization, or verify the repository URL."
          : "The repository could not be analyzed. Try again or check the URL."
      });
      return;
    }

    const job = {
      id: randomUUID(),
      engine: "real-v1",
      status: "report_ready",
      tier,
      organization: context.organization.slug,
      queue: plan.label,
      workers: plan.workers,
      sourceUrl: result.repository?.url || body.sourceUrl,
      repository: result.repository,
      scanDepth: body.scanDepth || "full",
      createdAt: new Date().toISOString(),
      scanned: result.scanned,
      summary: result.summary,
      findings: result.findings
    };

    // Persist the report so an approved repair can load the findings later.
    // Keep only the most recent reports per org to bound storage.
    await write(async (state) => {
      const record = {
        id: job.id,
        organizationId: context.organization.id,
        sourceUrl: job.sourceUrl,
        createdAt: job.createdAt,
        summary: job.summary,
        findings: job.findings
      };
      const others = state.reports.filter((r) => r.organizationId !== context.organization.id);
      const mine = [record, ...state.reports.filter((r) => r.organizationId === context.organization.id)]
        .slice(0, MAX_REPORTS_PER_ORG);
      return { ...state, reports: [...mine, ...others] };
    });

    json(res, 200, job);
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
