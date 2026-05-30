import { json, readBody } from "./_lib.js";
import * as repo from "./_repo.js";
import { currentUserContext, publicOrganization, slugify } from "./_auth.js";

async function listOrgs(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in required" });
    return;
  }
  json(res, 200, { organizations: context.organizations.map(publicOrganization) });
}

async function createOrg(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in required" });
    return;
  }
  const body = await readBody(req);
  const name = String(body.name || "").trim();
  if (!name) {
    json(res, 400, { error: "Organization name is required." });
    return;
  }

  const createdOrg = await repo.createOrganizationForUser(name, slugify(name), context.user.id);
  json(res, 200, { organization: publicOrganization(createdOrg) });
}

export default async function handler(req, res) {
  try {
    if (req.method === "GET") return await listOrgs(req, res);
    if (req.method === "POST") return await createOrg(req, res);
    json(res, 405, { error: "Method not allowed" });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
