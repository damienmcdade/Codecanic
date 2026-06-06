import { createHmac } from "node:crypto";
import { secret, isProductionLike, currentUserContext } from "./_auth.js";

const DEFAULT_APP_URL = "https://codecanic.app";

// Validity window for OAuth/connector state tokens.
export const STATE_TTL_MS = 10 * 60_000;

const plans = {
  Free: { name: "Free", queueDelayMs: 200, workers: 24, label: "Priority queue", adFree: false, monthlyScanLimit: 50 },
  Pro: { name: "Pro", queueDelayMs: 0, workers: 48, label: "Pro queue", adFree: true, monthlyScanLimit: null }
};

const connectorConfig = {
  GitHub: {
    env: "GITHUB_CLIENT_ID",
    authBase: "https://github.com/login/oauth/authorize",
    scopes: "repo read:org workflow"
  },
  Vercel: {
    env: "VERCEL_CLIENT_ID",
    authBase: "https://vercel.com/oauth/authorize",
    scopes: ""
  },
  GitLab: {
    env: "GITLAB_CLIENT_ID",
    authBase: "https://gitlab.com/oauth/authorize",
    scopes: "read_repository api"
  },
  Bitbucket: {
    env: "BITBUCKET_CLIENT_ID",
    authBase: "https://bitbucket.org/site/oauth2/authorize",
    scopes: "repository account"
  },
  Railway: {
    env: "RAILWAY_TOKEN",
    authBase: "https://railway.app/account/tokens",
    scopes: ""
  },
  Xcode: {
    env: "APPLE_TEAM_ID",
    authBase: "https://developer.apple.com/account",
    scopes: ""
  }
};

export function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}

// Parse a request's URL with a safe (non-security-sensitive) base — the base is
// only used to resolve the relative req.url path/query, never trusted as origin.
export function requestUrl(req) {
  return new URL(req.url, `http://${req.headers.host || "localhost"}`);
}

// Canonical app origin. Never derives security-sensitive URLs (OAuth redirect,
// email links) from the attacker-controllable Host header in production.
export function appBaseUrl(req) {
  if (process.env.CODECANIC_APP_URL) return process.env.CODECANIC_APP_URL.replace(/\/$/, "");
  if (isProductionLike()) return DEFAULT_APP_URL;
  const proto = (req.headers["x-forwarded-proto"] || "http").split(",")[0];
  return `${proto}://${req.headers.host || "localhost"}`;
}

// Signed, expiring state token for OAuth/connector round-trips (HMAC over the
// session secret). Shared by oauth.js + connectors.js so the signing scheme can
// never drift between them. secret() refuses the dev fallback in production.
export function signState(payload) {
  const value = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret()).update(value).digest("base64url");
  return `${value}.${signature}`;
}

export function verifyState(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [value, signature] = token.split(".");
  const expected = createHmac("sha256", secret()).update(value).digest("base64url");
  if (signature.length !== expected.length || signature !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!payload.expiresAt || payload.expiresAt < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// Resolve the active org for a request from a user context: prefer the
// X-Codecanic-Org header / ?organization= slug-or-id, else the first org.
export function orgFromRequest(req, context, url) {
  const u = url || requestUrl(req);
  const requested = req.headers["x-codecanic-org"] || u.searchParams.get("organization") || null;
  const orgs = context.organizations || [];
  let organization = null;
  if (requested) organization = orgs.find((o) => o.slug === requested || o.id === requested) || null;
  return organization || orgs[0] || null;
}

export async function resolveOrgContext(req) {
  const context = await currentUserContext(req);
  if (!context) return { authenticated: false };
  const organization = orgFromRequest(req, context);
  return { authenticated: true, ...context, organization };
}

// A client (4xx) error whose message is safe to return to the caller. Handlers
// throw these for invalid input; everything else is treated as a 500. This
// replaces fragile message-string sniffing in the handler catch blocks.
export class ClientError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = "ClientError";
    this.statusCode = statusCode;
    this.expose = true;
  }
}

export function badRequest(message) {
  return new ClientError(message, 400);
}

export function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new ClientError("Request body is too large."));
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new ClientError("Request body must be valid JSON."));
      }
    });
    req.on("error", reject);
  });
}

export function planFor(name) {
  return plans[name] || plans.Free;
}

export function entitlements(name) {
  const p = planFor(name);
  return { plan: p.name, adFree: p.adFree, monthlyScanLimit: p.monthlyScanLimit };
}

export function getConnector(name) {
  return connectorConfig[name];
}

// Real scanning lives in ./_scanner.js (scanRepository / scanDirectory).
// The previous hardcoded buildFindings()/summarize() simulation was removed.
