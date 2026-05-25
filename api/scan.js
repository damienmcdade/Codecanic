import { buildFindings, json, planFor, readBody, resolveOrgContext, summarize } from "./_lib.js";
import { randomUUID } from "node:crypto";

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
    const tier = body.tier || context.organization.plan || "Free";
    const plan = planFor(tier);
    const findings = buildFindings(body);
    const job = {
      id: randomUUID(),
      status: "report_ready",
      tier,
      organization: context.organization.slug,
      queue: plan.label,
      workers: plan.workers,
      sourceUrl: body.sourceUrl || "Connected workspace",
      scanDepth: body.scanDepth || "full",
      createdAt: new Date().toISOString(),
      estimatedRuntimeMs: plan.queueDelayMs + findings.length * 180,
      summary: summarize(findings),
      findings
    };

    json(res, 200, job);
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
