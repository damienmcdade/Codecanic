import { json, planFor, readBody, resolveOrgContext } from "./_lib.js";
import { randomUUID } from "node:crypto";

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

    const body = await readBody(req);
    const findingIds = Array.isArray(body.findingIds) ? body.findingIds : [];
    if (!findingIds.length) {
      json(res, 400, { error: "At least one finding must be selected." });
      return;
    }

    const plan = planFor(body.tier || context.organization.plan || "Free");
    json(res, 200, {
      id: randomUUID(),
      status: "queued",
      organization: context.organization.slug,
      findingIds,
      branchName: `codecanic/${context.organization.slug}-repair-${Date.now()}`,
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
