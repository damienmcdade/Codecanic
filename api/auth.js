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
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const loginAttempts = new Map();

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function clientKey(req, email) {
  const fwd = req.headers["x-forwarded-for"] || "";
  const ip = String(fwd).split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
  return `${ip}|${email}`;
}

function checkLoginLockout(key) {
  const entry = loginAttempts.get(key);
  if (!entry) return null;
  const now = Date.now();
  if (entry.lockUntil && entry.lockUntil > now) {
    return { retryAfterMs: entry.lockUntil - now };
  }
  if (entry.lockUntil && entry.lockUntil <= now) {
    loginAttempts.delete(key);
  }
  return null;
}

function recordLoginFailure(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key) || { count: 0, lockUntil: 0 };
  entry.count += 1;
  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    entry.lockUntil = now + LOGIN_LOCKOUT_MS;
  }
  loginAttempts.set(key, entry);
}

function clearLoginFailures(key) {
  loginAttempts.delete(key);
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
  const key = clientKey(req, email);

  const lockout = checkLoginLockout(key);
  if (lockout) {
    const retryAfter = Math.ceil(lockout.retryAfterMs / 1000);
    res.setHeader("Retry-After", String(retryAfter));
    json(res, 429, { error: `Too many failed attempts. Try again in ${retryAfter}s.` });
    return;
  }

  const state = await read();
  const user = state.users.find((entry) => entry.email === email);
  const ok = user ? await verifyPassword(password, user.passwordHash) : false;
  if (!user || !ok) {
    recordLoginFailure(key);
    json(res, 401, { error: "Email or password is incorrect." });
    return;
  }
  clearLoginFailures(key);

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
