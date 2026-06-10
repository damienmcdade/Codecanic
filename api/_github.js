// GitHub App support — least-privilege, per-repo access (the trust fix).
//
// A GitHub App lets users grant access to *specific* repos with fine-grained,
// short-lived installation tokens, instead of the broad all-or-nothing OAuth
// `repo` scope. When GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY are configured and
// an org has installed the app, scans/repairs mint a fresh installation token;
// otherwise they fall back to the org's OAuth token.
import { createSign } from "node:crypto";
import * as repo from "./_repo.js";
import { decryptSecret } from "./_crypto.js";
import { fetchWithTimeout } from "./_http.js";

const b64url = (input) => Buffer.from(input).toString("base64url");

export function githubAppConfigured() {
  return Boolean(process.env.GITHUB_APP_ID && process.env.GITHUB_APP_PRIVATE_KEY);
}

function privateKey() {
  // Env vars often store PEM newlines as literal "\n".
  return process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, "\n");
}

// Short-lived JWT signed as the App (RS256), used to mint installation tokens.
export function appJwt(now = Math.floor(Date.now() / 1000)) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: process.env.GITHUB_APP_ID }));
  const data = `${header}.${payload}`;
  const sig = createSign("RSA-SHA256").update(data).sign(privateKey());
  return `${data}.${b64url(sig)}`;
}

export async function installationToken(installationId) {
  const res = await fetchWithTimeout(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt()}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Codecanic",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 201 && data.token) return { token: data.token, expiresAt: data.expires_at };
  throw new Error(`GitHub App token exchange failed (${res.status}): ${data.message || "unknown"}`);
}

// Fetch an installation's metadata using the App JWT. Used to verify ownership
// of an installation_id reported back to the App's setup callback before we
// store it (so a user can't bind an arbitrary installation to their org).
// Returns { account: { login, type } } or null if the lookup isn't possible.
export async function getInstallation(installationId) {
  if (!githubAppConfigured()) return null;
  const res = await fetchWithTimeout(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}`, {
    headers: {
      Authorization: `Bearer ${appJwt()}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Codecanic",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  const data = await res.json().catch(() => ({}));
  if (res.status !== 200) throw new Error(`GitHub App installation lookup failed (${res.status}): ${data.message || "unknown"}`);
  return data;
}

const HOST_PROVIDER = {
  "github.com": "GitHub", "www.github.com": "GitHub", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket"
};

// Resolve a usable git token for a host: prefer a least-privilege GitHub App
// installation token; fall back to the stored OAuth token.
export async function resolveRepoToken(host, organizationId) {
  const provider = HOST_PROVIDER[host];
  if (!provider) return null;
  if (provider === "GitHub" && githubAppConfigured()) {
    const installationId = await repo.getGithubInstallation(organizationId);
    if (installationId) {
      try { return (await installationToken(installationId)).token; } catch { /* fall through to OAuth */ }
    }
  }
  const cred = await repo.findConnectorCred(provider, organizationId);
  if (!cred?.accessToken) return null;
  try { return decryptSecret(cred.accessToken); } catch { return null; }
}

// Cheap "is there any usable connection?" check for synchronous validation —
// avoids minting a token just to decide whether to 422.
export async function hasConnection(host, organizationId) {
  const provider = HOST_PROVIDER[host];
  if (!provider) return false;
  if (provider === "GitHub" && githubAppConfigured() && (await repo.getGithubInstallation(organizationId))) return true;
  const cred = await repo.findConnectorCred(provider, organizationId);
  return Boolean(cred?.accessToken);
}
