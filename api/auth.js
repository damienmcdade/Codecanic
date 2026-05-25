import { randomUUID } from "node:crypto";
import { json, readBody } from "./_lib.js";
import { read, write } from "./_data.js";
import {
  buildSessionCookie,
  clearSessionCookie,
  createSession,
  currentUserContext,
  destroySession,
  hashPassword,
  publicOrganization,
  publicUser,
  slugify,
  verifyPassword,
  verifySessionToken
} from "./_auth.js";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

async function uniqueSlug(state, base) {
  let candidate = base;
  let suffix = 1;
  while (state.organizations.some((org) => org.slug === candidate)) {
    suffix += 1;
    candidate = `${base}-${suffix}`;
  }
  return candidate;
}

async function signup(req, res) {
  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const name = String(body.name || "").trim() || email.split("@")[0];
  const orgName = String(body.organization || `${name}'s workspace`).trim();

  if (!emailRegex.test(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }
  if (password.length < 8) {
    json(res, 400, { error: "Password must be at least 8 characters." });
    return;
  }

  const existing = await read();
  if (existing.users.some((user) => user.email === email)) {
    json(res, 409, { error: "An account with that email already exists." });
    return;
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();
  const user = { id: randomUUID(), email, name, passwordHash, createdAt: now };

  let createdOrg;
  let createdMembership;
  await write(async (state) => {
    const slug = await uniqueSlug(state, slugify(orgName));
    createdOrg = { id: randomUUID(), name: orgName, slug, plan: "Free", createdAt: now };
    createdMembership = {
      id: randomUUID(),
      userId: user.id,
      organizationId: createdOrg.id,
      role: "owner",
      createdAt: now
    };
    return {
      ...state,
      users: [...state.users, user],
      organizations: [...state.organizations, createdOrg],
      memberships: [...state.memberships, createdMembership]
    };
  });

  const token = await createSession(user.id);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  json(res, 200, {
    user: publicUser(user),
    organizations: [publicOrganization(createdOrg)],
    activeOrganization: publicOrganization(createdOrg)
  });
}

async function login(req, res) {
  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  const state = await read();
  const user = state.users.find((entry) => entry.email === email);
  const ok = user ? await verifyPassword(password, user.passwordHash) : false;
  if (!user || !ok) {
    json(res, 401, { error: "Email or password is incorrect." });
    return;
  }

  const memberships = state.memberships.filter((m) => m.userId === user.id);
  const organizations = memberships
    .map((m) => state.organizations.find((org) => org.id === m.organizationId))
    .filter(Boolean)
    .map(publicOrganization);

  const token = await createSession(user.id);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  json(res, 200, {
    user: publicUser(user),
    organizations,
    activeOrganization: organizations[0] || null
  });
}

async function logout(req, res) {
  const cookieHeader = req.headers.cookie || "";
  const token = cookieHeader
    .split(";")
    .map((pair) => pair.trim())
    .find((pair) => pair.startsWith("codecanic_session="));
  if (token) {
    const value = decodeURIComponent(token.split("=")[1] || "");
    const sessionId = verifySessionToken(value);
    if (sessionId) await destroySession(sessionId);
  }
  res.setHeader("Set-Cookie", clearSessionCookie());
  json(res, 200, { status: "signed_out" });
}

async function me(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 200, { user: null, organizations: [] });
    return;
  }
  json(res, 200, {
    user: publicUser(context.user),
    organizations: context.organizations.map(publicOrganization)
  });
}

export default async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.pathname.replace(/^\/api\/auth\/?/, "");
  try {
    if (action === "signup" && req.method === "POST") return await signup(req, res);
    if (action === "login" && req.method === "POST") return await login(req, res);
    if (action === "logout" && req.method === "POST") return await logout(req, res);
    if (action === "me" && req.method === "GET") return await me(req, res);
    json(res, 404, { error: "Unknown auth action" });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
