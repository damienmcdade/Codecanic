import { createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { read, write } from "./_data.js";

const scryptAsync = promisify(scrypt);
const SESSION_DAYS = 14;
const SESSION_COOKIE = "codecanic_session";
const KEY_LENGTH = 64;

function isProductionLike() {
  return Boolean(
    process.env.NODE_ENV === "production" ||
      process.env.VERCEL === "1" ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_PROJECT_ID
  );
}

const DEV_FALLBACK_SECRET = "codecanic-development-secret-do-not-use-in-prod";

function secret() {
  const value = process.env.CODECANIC_SESSION_SECRET;
  if (value && value.length >= 32 && value !== DEV_FALLBACK_SECRET) return value;
  if (isProductionLike()) {
    throw new Error(
      "CODECANIC_SESSION_SECRET must be set to a 32+ character value in production. Refusing to use insecure fallback."
    );
  }
  return value || DEV_FALLBACK_SECRET;
}

export function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || `org-${randomBytes(3).toString("hex")}`;
}

export async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const derived = await scryptAsync(password, salt, KEY_LENGTH);
  return `${salt}:${derived.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, hex] = stored.split(":");
  const derived = await scryptAsync(password, salt, KEY_LENGTH);
  const expected = Buffer.from(hex, "hex");
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(expected, derived);
}

function sign(value) {
  return createHmac("sha256", secret()).update(value).digest("hex");
}

export function signSessionToken(sessionId) {
  return `${sessionId}.${sign(sessionId)}`;
}

export function verifySessionToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [sessionId, signature] = token.split(".");
  const expected = sign(sessionId);
  if (signature.length !== expected.length) return null;
  if (!timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"))) return null;
  return sessionId;
}

export function parseCookies(header = "") {
  return Object.fromEntries(
    header
      .split(";")
      .map((pair) => pair.trim())
      .filter(Boolean)
      .map((pair) => {
        const idx = pair.indexOf("=");
        if (idx === -1) return [pair, ""];
        return [pair.slice(0, idx), decodeURIComponent(pair.slice(idx + 1))];
      })
  );
}

export function buildSessionCookie(token, { maxAgeDays = SESSION_DAYS, secure } = {}) {
  const attrs = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(maxAgeDays * 86400)}`
  ];
  if (secure ?? isProductionLike()) attrs.push("Secure");
  return attrs.join("; ");
}

export function clearSessionCookie() {
  const attrs = [`${SESSION_COOKIE}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (isProductionLike()) attrs.push("Secure");
  return attrs.join("; ");
}

const MAX_SESSIONS_PER_USER = 5;

export async function createSession(userId) {
  const sessionId = randomUUID();
  const session = {
    id: sessionId,
    userId,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString()
  };
  await write(async (state) => {
    const now = Date.now();
    const active = state.sessions.filter((s) => new Date(s.expiresAt).getTime() > now);
    const mine = active.filter((s) => s.userId === userId).slice(0, MAX_SESSIONS_PER_USER - 1);
    const others = active.filter((s) => s.userId !== userId);
    return { ...state, sessions: [session, ...mine, ...others] };
  });
  return signSessionToken(sessionId);
}

export async function destroySession(sessionId) {
  await write(async (state) => ({
    ...state,
    sessions: state.sessions.filter((session) => session.id !== sessionId)
  }));
}

export async function currentSession(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const token = cookies[SESSION_COOKIE];
  const sessionId = verifySessionToken(token);
  if (!sessionId) return null;
  const state = await read();
  const session = state.sessions.find((entry) => entry.id === sessionId);
  if (!session) return null;
  if (new Date(session.expiresAt).getTime() < Date.now()) return null;
  const user = state.users.find((entry) => entry.id === session.userId);
  if (!user) return null;
  return { session, user };
}

export async function currentUserContext(req) {
  const auth = await currentSession(req);
  if (!auth) return null;
  const state = await read();
  const memberships = state.memberships.filter((m) => m.userId === auth.user.id);
  const organizations = memberships
    .map((m) => state.organizations.find((org) => org.id === m.organizationId))
    .filter(Boolean);
  return { ...auth, memberships, organizations };
}

export function publicUser(user) {
  if (!user) return null;
  const { id, email, name, createdAt } = user;
  return { id, email, name, createdAt };
}

export function publicOrganization(org) {
  if (!org) return null;
  const { id, name, slug, plan, createdAt } = org;
  return { id, name, slug, plan, createdAt };
}
