import { randomUUID } from "node:crypto";
import { json, readBody } from "./_lib.js";
import { read, write } from "./_data.js";
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

  const now = new Date().toISOString();
  let createdOrg;
  await write(async (state) => {
    let slug = slugify(name);
    let suffix = 1;
    while (state.organizations.some((org) => org.slug === slug)) {
      suffix += 1;
      slug = `${slugify(name)}-${suffix}`;
    }
    createdOrg = { id: randomUUID(), name, slug, plan: "Free", createdAt: now };
    const membership = {
      id: randomUUID(),
      userId: context.user.id,
      organizationId: createdOrg.id,
      role: "owner",
      createdAt: now
    };
    return {
      ...state,
      organizations: [...state.organizations, createdOrg],
      memberships: [...state.memberships, membership]
    };
  });
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
