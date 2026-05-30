import { json, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";

// GET /api/jobs            → recent jobs for the active organization
// GET /api/jobs/<id>       → one job (status, and result/error when finished)
export default async function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }
  try {
    const context = await resolveOrgContext(req);
    if (!context.authenticated) {
      json(res, 401, { error: "Sign in required." });
      return;
    }
    if (!context.organization) {
      json(res, 400, { error: "Select an organization first." });
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const id = url.pathname.replace(/^\/api\/jobs\/?/, "");

    if (!id) {
      const jobs = await repo.recentJobs(context.organization.id);
      json(res, 200, { jobs });
      return;
    }

    const job = await repo.getJob(id, context.organization.id);
    if (!job) {
      json(res, 404, { error: "Job not found." });
      return;
    }
    json(res, 200, {
      id: job.id,
      type: job.type,
      status: job.status,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      finishedAt: job.finishedAt,
      // Surface the payload only result/error — never the internal payload.
      result: job.status === "succeeded" ? job.result : undefined,
      error: job.status === "failed" ? job.error : undefined
    });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
