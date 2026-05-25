import { buildFindings, json, planFor, readBody, summarize } from "./_lib.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  try {
    const body = await readBody(req);
    const tier = body.tier || "Free";
    const plan = planFor(tier);
    const findings = buildFindings(body);
    const job = {
      id: crypto.randomUUID(),
      status: "report_ready",
      tier,
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
