import { json, readBody, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";
import { logger } from "./_log.js";

// GET    /api/suppressions               → list suppressed finding fingerprints
// POST   /api/suppressions {fingerprint} → suppress a finding (hidden from scans)
// DELETE /api/suppressions {fingerprint} → un-suppress
export default async function handler(req, res) {
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
    const orgId = context.organization.id;

    if (req.method === "GET") {
      json(res, 200, { suppressions: await repo.listSuppressions(orgId) });
      return;
    }
    if (req.method === "POST" || req.method === "DELETE") {
      const body = await readBody(req);
      const fingerprint = String(body.fingerprint || "").trim();
      if (!fingerprint) {
        json(res, 400, { error: "A finding fingerprint is required." });
        return;
      }
      if (req.method === "POST") {
        await repo.addSuppression({ organizationId: orgId, fingerprint, reason: body.reason, createdBy: context.user.id });
        json(res, 200, { status: "suppressed", fingerprint });
      } else {
        await repo.removeSuppression(orgId, fingerprint);
        json(res, 200, { status: "unsuppressed", fingerprint });
      }
      return;
    }
    json(res, 405, { error: "Method not allowed" });
  } catch (error) {
    const expose = error?.expose === true;
    const statusCode = expose ? error.statusCode || 400 : 500;
    if (!expose) logger.error("suppressions.handler_error", { err: error });
    json(res, statusCode, { error: expose ? error.message : "Request failed." });
  }
}
