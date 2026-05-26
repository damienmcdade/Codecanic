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
  if (password.length < 15) {
    json(res, 400, { error: "Password must be at least 15 characters." });
    return;
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    json(res, 400, {
      error: "Password must include uppercase, lowercase, a digit, and a symbol."
    });
    return;
  }
  if (body.acceptTerms !== true) {
    json(res, 400, { error: "You must accept the Terms of Service and Privacy Policy to create an account." });
    return;
  }
  const age = Number(body.age);
  if (!Number.isFinite(age) || age < 16) {
    json(res, 400, { error: "You must confirm you are 16 or older to create an account (GDPR digital age of consent)." });
    return;
  }

  const existing = await read();
  if (existing.users.some((user) => user.email === email)) {
    json(res, 409, { error: "An account with that email already exists." });
    return;
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();
  const user = {
    id: randomUUID(),
    email,
    name,
    passwordHash,
    createdAt: now,
    termsAcceptedAt: now,
    privacyAcceptedAt: now,
    marketingOptIn: body.marketingOptIn === true,
    ageConfirmed: true
  };

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

async function exportData(req, res) {
  const ctx = await currentUserContext(req);
  if (!ctx) {
    json(res, 401, { error: "Sign in to export your data." });
    return;
  }
  const state = await read();
  const userId = ctx.user.id;
  const myMemberships = state.memberships.filter((m) => m.userId === userId);
  const myOrgIds = myMemberships.map((m) => m.organizationId);
  const payload = {
    exportedAt: new Date().toISOString(),
    notice:
      "This file contains personal data Codecanic stores about your account. Provider access tokens are redacted for safety. To revoke them, disconnect via the Connection Wizard or contact support.",
    user: {
      id: ctx.user.id,
      email: ctx.user.email,
      name: ctx.user.name,
      createdAt: ctx.user.createdAt,
      termsAcceptedAt: ctx.user.termsAcceptedAt || null,
      privacyAcceptedAt: ctx.user.privacyAcceptedAt || null,
      marketingOptIn: ctx.user.marketingOptIn === true
    },
    organizations: state.organizations
      .filter((o) => myOrgIds.includes(o.id))
      .map(publicOrganization),
    memberships: myMemberships.map((m) => ({
      organizationId: m.organizationId,
      role: m.role,
      createdAt: m.createdAt
    })),
    connectorCredentials: state.connectorCreds
      .filter((c) => c.userId === userId || myOrgIds.includes(c.organizationId))
      .map((c) => ({
        provider: c.provider,
        organizationId: c.organizationId,
        tokenType: c.tokenType,
        scope: c.scope,
        updatedAt: c.updatedAt,
        accessToken: "***redacted***",
        refreshToken: c.refreshToken ? "***redacted***" : null
      })),
    activeSessions: state.sessions
      .filter((s) => s.userId === userId)
      .map((s) => ({ createdAt: s.createdAt, expiresAt: s.expiresAt }))
  };
  res.setHeader("Content-Disposition", 'attachment; filename="codecanic-data-export.json"');
  json(res, 200, payload);
}

async function deleteAccount(req, res) {
  const ctx = await currentUserContext(req);
  if (!ctx) {
    json(res, 401, { error: "Sign in to delete your account." });
    return;
  }
  const body = await readBody(req);
  const password = String(body.password || "");
  const confirm = String(body.confirm || "").trim().toUpperCase();
  if (!password) {
    json(res, 422, { error: "Re-enter your password to confirm." });
    return;
  }
  if (confirm !== "DELETE") {
    json(res, 422, { error: 'Type "DELETE" exactly to confirm.' });
    return;
  }
  const ok = await verifyPassword(password, ctx.user.passwordHash);
  if (!ok) {
    json(res, 401, { error: "Password is incorrect." });
    return;
  }

  const userId = ctx.user.id;
  await write(async (state) => {
    const myMemberships = state.memberships.filter((m) => m.userId === userId);
    const myOrgIds = myMemberships.map((m) => m.organizationId);
    const ownerCounts = new Map();
    for (const m of state.memberships) {
      if (m.role !== "owner") continue;
      ownerCounts.set(m.organizationId, (ownerCounts.get(m.organizationId) || 0) + 1);
    }
    const orgsToDelete = new Set();
    for (const m of myMemberships) {
      if (m.role === "owner" && ownerCounts.get(m.organizationId) === 1) {
        orgsToDelete.add(m.organizationId);
      }
    }
    return {
      ...state,
      users: state.users.filter((u) => u.id !== userId),
      sessions: state.sessions.filter((s) => s.userId !== userId),
      memberships: state.memberships.filter(
        (m) => m.userId !== userId && !orgsToDelete.has(m.organizationId)
      ),
      organizations: state.organizations.filter((o) => !orgsToDelete.has(o.id)),
      connectorCreds: state.connectorCreds.filter(
        (entry) => entry.userId !== userId && !orgsToDelete.has(entry.organizationId)
      )
    };
  });

  res.setHeader("Set-Cookie", clearSessionCookie());
  json(res, 200, { status: "account_deleted" });
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
    if (action === "account" && (req.method === "DELETE" || req.method === "POST")) {
      return await deleteAccount(req, res);
    }
    if (action === "export" && req.method === "GET") return await exportData(req, res);
    json(res, 404, { error: "Unknown auth action" });
  } catch (error) {
    console.error("[auth error]", error);
    const isClientError = /^(Request body|Provider|Apple|Railway|Password|Email|Enter|At least|Sign in|Type "DELETE"|Re-enter|You|CODECANIC_SESSION_SECRET)/.test(
      error?.message || ""
    );
    json(res, isClientError ? 400 : 500, {
      error: isClientError ? error.message : "Request failed."
    });
  }
}
