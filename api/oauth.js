import { createHmac, randomUUID } from "node:crypto";
import { getConnector, json, readBody } from "./_lib.js";
import * as repo from "./_repo.js";
import { currentUserContext } from "./_auth.js";
import { encryptSecret } from "./_crypto.js";
import { githubAppConfigured } from "./_github.js";

const manualProviders = new Set(["Railway", "Xcode"]);

const tokenExchange = {
  GitHub: {
    url: "https://github.com/login/oauth/access_token",
    accept: "application/json"
  },
  Vercel: {
    url: "https://api.vercel.com/v2/oauth/access_token"
  },
  GitLab: {
    url: "https://gitlab.com/oauth/token"
  },
  Bitbucket: {
    url: "https://bitbucket.org/site/oauth2/access_token",
    basicAuth: true
  }
};

function signState(payload) {
  const secret = process.env.CODECANIC_SESSION_SECRET || "codecanic-development-secret-do-not-use-in-prod";
  const value = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${signature}`;
}

function verifyState(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [value, signature] = token.split(".");
  const secret = process.env.CODECANIC_SESSION_SECRET || "codecanic-development-secret-do-not-use-in-prod";
  const expected = createHmac("sha256", secret).update(value).digest("base64url");
  if (signature.length !== expected.length) return null;
  if (signature !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!payload.expiresAt || payload.expiresAt < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function redirectUriFor(req, provider) {
  if (process.env.CODECANIC_REDIRECT_URI) return process.env.CODECANIC_REDIRECT_URI;
  const protocol = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || "codecanic.local";
  return `${protocol}://${host}/api/oauth/callback?provider=${encodeURIComponent(provider)}`;
}

function clientSecretEnvFor(connectorEnv) {
  return connectorEnv.replace(/_CLIENT_ID$/, "_CLIENT_SECRET");
}

async function start(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const provider = url.searchParams.get("provider");
  const connector = provider ? getConnector(provider) : null;
  if (!connector) {
    json(res, 400, { error: "Unknown provider" });
    return;
  }

  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to connect providers." });
    return;
  }
  const requestedOrg =
    req.headers["x-codecanic-org"] || url.searchParams.get("organization") || null;
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization before connecting providers." });
    return;
  }

  const clientId = process.env[connector.env];
  if (!clientId) {
    json(res, 200, {
      provider,
      configured: false,
      status: "configuration_required",
      requiredEnv: connector.env,
      message: `${provider} needs ${connector.env} before live authorization can start.`
    });
    return;
  }

  if (provider === "Railway" || provider === "Xcode") {
    json(res, 200, {
      provider,
      status: "manual_token_required",
      message: `${provider} uses a manual token. Paste a personal access token in settings.`
    });
    return;
  }

  const state = signState({
    nonce: randomUUID(),
    userId: context.user.id,
    organizationId: organization.id,
    provider,
    expiresAt: Date.now() + 10 * 60_000
  });
  const authUrl = new URL(connector.authBase);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUriFor(req, provider));
  authUrl.searchParams.set("state", state);
  if (connector.scopes) authUrl.searchParams.set("scope", connector.scopes);
  if (provider === "GitLab") authUrl.searchParams.set("response_type", "code");
  json(res, 200, { provider, status: "authorization_ready", authUrl: authUrl.toString() });
}

async function exchangeCode(provider, code, req) {
  const connector = getConnector(provider);
  const exchange = tokenExchange[provider];
  if (!connector || !exchange) throw new Error("Provider not supported for token exchange");

  const clientId = process.env[connector.env];
  const clientSecret = process.env[clientSecretEnvFor(connector.env)];
  if (!clientId || !clientSecret) {
    throw new Error(`${provider} client secret is missing (${clientSecretEnvFor(connector.env)})`);
  }

  const params = new URLSearchParams({
    code,
    grant_type: "authorization_code",
    redirect_uri: redirectUriFor(req, provider)
  });
  const headers = { Accept: exchange.accept || "application/json" };
  if (exchange.basicAuth) {
    headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else {
    params.set("client_id", clientId);
    params.set("client_secret", clientSecret);
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }

  const response = await fetch(exchange.url, { method: "POST", headers, body: params.toString() });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = Object.fromEntries(new URLSearchParams(text));
  }
  if (!response.ok || data.error) {
    const message = data.error_description || data.error || `Token exchange failed (${response.status})`;
    throw new Error(message);
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || null,
    tokenType: data.token_type || "bearer",
    scope: data.scope || null,
    expiresIn: data.expires_in || null
  };
}

function renderHtml(title, message, { provider = null, success = false, nonce = "" } = {}) {
  const payload = JSON.stringify({
    type: "codecanic:connector",
    provider,
    success,
    message
  }).replace(/</g, "\\u003c");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body style="font-family:system-ui;padding:32px;background:#0a1019;color:#f8fafc;">
<h1 style="color:${success ? "#14b8a6" : "#f87171"};">${title}</h1>
<p>${message}</p>
<p><a href="/" style="color:#2dd4bf;">Return to Codecanic</a></p>
<script nonce="${nonce}">
(function(){
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(${payload}, window.location.origin);
      setTimeout(function(){ window.close(); }, 600);
      return;
    }
  } catch (err) {}
  setTimeout(function(){ window.location.href = "/?connected=" + ${success ? '"1"' : '"0"'}; }, 1500);
})();
</script>
</body></html>`;
}

function sendHtml(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}

async function callback(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const provider = url.searchParams.get("provider");
  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");
  const error = url.searchParams.get("error_description") || url.searchParams.get("error");

  if (error) {
    sendHtml(res, 400, renderHtml("Authorization cancelled", error, { provider, success: false, nonce: req.cspNonce }));
    return;
  }
  if (!provider || !code || !stateToken) {
    sendHtml(
      res,
      400,
      renderHtml("Missing parameters", "Provider, code, and state are required.", { provider, success: false, nonce: req.cspNonce })
    );
    return;
  }
  const payload = verifyState(stateToken);
  if (!payload || payload.provider !== provider) {
    sendHtml(
      res,
      400,
      renderHtml("State validation failed", "OAuth state is invalid or expired.", { provider, success: false, nonce: req.cspNonce })
    );
    return;
  }

  try {
    const token = await exchangeCode(provider, code, req);
    const now = new Date().toISOString();
    const orgValid = await repo.membershipExists(payload.userId, payload.organizationId);
    if (!orgValid) {
      sendHtml(
        res,
        403,
        renderHtml("Access denied", "You no longer have access to that organization.", {
          provider,
          success: false
        })
      );
      return;
    }

    await repo.upsertConnectorCred({
      provider,
      organizationId: payload.organizationId,
      userId: payload.userId,
      accessToken: encryptSecret(token.accessToken),
      refreshToken: token.refreshToken ? encryptSecret(token.refreshToken) : null,
      tokenType: token.tokenType,
      scope: token.scope,
      expiresIn: token.expiresIn,
      updatedAt: now
    });

    sendHtml(
      res,
      200,
      renderHtml(`${provider} connected`, "Authorization complete. You can close this window.", {
        provider,
        success: true,
        nonce: req.cspNonce
      })
    );
  } catch (err) {
    sendHtml(res, 502, renderHtml("Authorization failed", err.message, { provider, success: false, nonce: req.cspNonce }));
  }
}

async function manual(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to connect providers." });
    return;
  }
  const body = await readBody(req);
  const provider = typeof body.provider === "string" ? body.provider : "";
  const token = typeof body.token === "string" ? body.token.trim() : "";
  const connector = getConnector(provider);
  if (!connector || !manualProviders.has(provider)) {
    json(res, 400, { error: "Provider does not support manual token connection." });
    return;
  }
  if (!token) {
    json(res, 422, { error: "Paste a token to continue." });
    return;
  }
  if (provider === "Xcode" && !/^[A-Z0-9]{10}$/i.test(token)) {
    json(res, 422, { error: "Apple Team ID must be 10 alphanumeric characters." });
    return;
  }
  if (provider === "Railway" && token.length < 16) {
    json(res, 422, { error: "Railway token looks too short. Generate a token at railway.app/account/tokens." });
    return;
  }
  const requestedOrg = req.headers["x-codecanic-org"] || null;
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization before connecting providers." });
    return;
  }

  const now = new Date().toISOString();
  await repo.upsertConnectorCred({
    provider,
    organizationId: organization.id,
    userId: context.user.id,
    accessToken: encryptSecret(token),
    refreshToken: null,
    tokenType: "manual",
    scope: null,
    expiresIn: null,
    updatedAt: now
  });

  json(res, 200, {
    provider,
    status: "connected",
    connectedAt: now,
    message: `${provider} connected for ${organization.name}.`
  });
}

async function disconnect(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in required." });
    return;
  }
  const body = await readBody(req);
  const provider = typeof body.provider === "string" ? body.provider : "";
  if (!provider) {
    json(res, 400, { error: "Provider is required." });
    return;
  }
  const requestedOrg = req.headers["x-codecanic-org"] || null;
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization first." });
    return;
  }

  await repo.deleteConnectorCred(provider, organization.id);

  json(res, 200, { provider, status: "disconnected" });
}

async function status(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in required" });
    return;
  }
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const requestedOrg = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 200, { connections: [] });
    return;
  }
  const creds = await repo.credsForOrg(organization.id);
  const connections = creds.map(({ provider, scope, tokenType, updatedAt }) => ({ provider, scope, tokenType, updatedAt }));
  json(res, 200, { connections });
}

function orgFromRequest(req, context, url) {
  const requested = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  return requested
    ? context.organizations.find((o) => o.slug === requested || o.id === requested)
    : context.organizations[0];
}

// GitHub App (least-privilege, per-repo): return the install URL with signed state.
async function githubAppStart(req, res) {
  const context = await currentUserContext(req);
  if (!context) { json(res, 401, { error: "Sign in required." }); return; }
  if (!githubAppConfigured() || !process.env.GITHUB_APP_SLUG) {
    json(res, 200, { configured: false, message: "GitHub App is not configured on this deployment; OAuth connect is available instead." });
    return;
  }
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const organization = orgFromRequest(req, context, url);
  if (!organization) { json(res, 400, { error: "Select an organization first." }); return; }
  const state = signState({ kind: "github-app", userId: context.user.id, organizationId: organization.id, expiresAt: Date.now() + 10 * 60_000 });
  const installUrl = `https://github.com/apps/${encodeURIComponent(process.env.GITHUB_APP_SLUG)}/installations/new?state=${encodeURIComponent(state)}`;
  json(res, 200, { configured: true, installUrl });
}

// GitHub redirects here (the App's Setup URL) after install with installation_id.
async function githubAppCallback(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const installationId = url.searchParams.get("installation_id");
  const payload = verifyState(url.searchParams.get("state"));
  if (!payload || payload.kind !== "github-app" || !installationId) {
    sendHtml(res, 400, renderHtml("GitHub App setup failed", "This link is invalid or expired. Start the connection again.", { provider: "GitHub", success: false, nonce: req.cspNonce }));
    return;
  }
  if (!(await repo.membershipExists(payload.userId, payload.organizationId))) {
    sendHtml(res, 403, renderHtml("Access denied", "You no longer have access to that organization.", { provider: "GitHub", success: false, nonce: req.cspNonce }));
    return;
  }
  await repo.setGithubInstallation(payload.organizationId, installationId);
  sendHtml(res, 200, renderHtml("GitHub App connected", "Codecanic can now access only the repositories you selected. Your code is never stored.", { provider: "GitHub", success: true, nonce: req.cspNonce }));
}

export default async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.pathname.replace(/^\/api\/oauth\/?/, "");
  try {
    if (action === "start" && req.method === "POST") return await start(req, res);
    if (action === "callback" && req.method === "GET") return await callback(req, res);
    if (action === "status" && req.method === "GET") return await status(req, res);
    if (action === "manual" && req.method === "POST") return await manual(req, res);
    if (action === "disconnect" && req.method === "POST") return await disconnect(req, res);
    if (action === "github-app" && req.method === "GET") return await githubAppStart(req, res);
    if (action === "github-app-callback" && req.method === "GET") return await githubAppCallback(req, res);
    json(res, 404, { error: "Unknown oauth action" });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
