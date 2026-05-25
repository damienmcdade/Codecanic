import { json, planFor, readBody } from "./_lib.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  try {
    const body = await readBody(req);
    const findingIds = Array.isArray(body.findingIds) ? body.findingIds : [];
    if (!findingIds.length) {
      json(res, 400, { error: "At least one finding must be selected." });
      return;
    }

    const plan = planFor(body.tier || "Free");
    json(res, 200, {
      id: crypto.randomUUID(),
      status: "queued",
      findingIds,
      branchName: `codecanic/repair-${Date.now()}`,
      pullRequestMode: "draft",
      workerCount: plan.workers,
      estimatedStartMs: plan.queueDelayMs,
      createdAt: new Date().toISOString(),
      nextStep: "Repair worker will generate patches, rerun validation, and prepare a reviewable pull request."
    });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
