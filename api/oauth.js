import { randomUUID } from "node:crypto";
import { getConnector, json, readBody, signState, verifyState, appBaseUrl, orgFromRequest, requestUrl, STATE_TTL_MS } from "./_lib.js";
import * as repo from "./_repo.js";
import { currentUserContext } from "./_auth.js";
import { encryptSecret } from "./_crypto.js";
import { githubAppConfigured, getInstallation } from "./_github.js";
import { fetchWithTimeout } from "./_http.js";
import { logger } from "./_log.js";

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

function redirectUriFor(req, provider) {
  if (process.env.CODECANIC_REDIRECT_URI) return process.env.CODECANIC_REDIRECT_URI;
  // appBaseUrl never trusts the Host header in production (shared in _lib.js).
  return `${appBaseUrl(req)}/api/oauth/callback?provider=${encodeURIComponent(provider)}`;
}

function clientSecretEnvFor(connectorEnv) {
  return connectorEnv.replace(/_CLIENT_ID$/, "_CLIENT_SECRET");
}

async function start(req, res) {
  const url = requestUrl(req);
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
  const organization = orgFromRequest(req, context, url);
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
    expiresAt: Date.now() + STATE_TTL_MS
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

  const response = await fetchWithTimeout(exchange.url, { method: "POST", headers, body: params.toString() });
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
  const url = requestUrl(req);
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
          success: false,
          nonce: req.cspNonce
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
  const organization = orgFromRequest(req, context);
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
  const organization = orgFromRequest(req, context);
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
  const organization = orgFromRequest(req, context);
  if (!organization) {
    json(res, 200, { connections: [] });
    return;
  }
  const creds = await repo.credsForOrg(organization.id);
  const connections = creds.map(({ provider, scope, tokenType, updatedAt }) => ({ provider, scope, tokenType, updatedAt }));
  json(res, 200, { connections });
}

// GitHub App (least-privilege, per-repo): return the install URL with signed state.
async function githubAppStart(req, res) {
  const context = await currentUserContext(req);
  if (!context) { json(res, 401, { error: "Sign in required." }); return; }
  if (!githubAppConfigured() || !process.env.GITHUB_APP_SLUG) {
    json(res, 200, { configured: false, message: "GitHub App is not configured on this deployment; OAuth connect is available instead." });
    return;
  }
  const url = requestUrl(req);
  const organization = orgFromRequest(req, context, url);
  if (!organization) { json(res, 400, { error: "Select an organization first." }); return; }
  const state = signState({ kind: "github-app", userId: context.user.id, organizationId: organization.id, expiresAt: Date.now() + 10 * 60_000 });
  const installUrl = `https://github.com/apps/${encodeURIComponent(process.env.GITHUB_APP_SLUG)}/installations/new?state=${encodeURIComponent(state)}`;
  json(res, 200, { configured: true, installUrl });
}

// Resolve the GitHub login connected to an org via its stored OAuth credential
// (used to verify a reported installation actually belongs to that account).
// Returns a lowercased login, or null if not resolvable.
async function connectedGithubLogin(organizationId) {
  try {
    const cred = await repo.findConnectorCred("GitHub", organizationId);
    if (!cred?.accessToken) return null;
    const token = decryptSecret(cred.accessToken);
    const r = await fetchWithTimeout("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "Codecanic" }
    });
    if (!r.ok) return null;
    const data = await r.json().catch(() => ({}));
    return data?.login ? String(data.login).toLowerCase() : null;
  } catch {
    return null;
  }
}

// GitHub redirects here (the App's Setup URL) after install with installation_id.
async function githubAppCallback(req, res) {
  const url = requestUrl(req);
  const installationId = url.searchParams.get("installation_id");
  const payload = verifyState(url.searchParams.get("state"));
  // S4: installation_id is attacker-supplied in the query — it must be numeric.
  if (!payload || payload.kind !== "github-app" || !installationId || !/^\d+$/.test(installationId)) {
    sendHtml(res, 400, renderHtml("GitHub App setup failed", "This link is invalid or expired. Start the connection again.", { provider: "GitHub", success: false, nonce: req.cspNonce }));
    return;
  }
  if (!(await repo.membershipExists(payload.userId, payload.organizationId))) {
    sendHtml(res, 403, renderHtml("Access denied", "You no longer have access to that organization.", { provider: "GitHub", success: false, nonce: req.cspNonce }));
    return;
  }

  // S4: verify ownership before storing. Look up the installation with the App
  // JWT and confirm its account matches the GitHub login connected to this org.
  // We only REJECT on a definite mismatch; if either side can't be resolved
  // (App JWT unavailable, or no OAuth cred to compare), we accept the numeric id
  // (the install flow itself is gated by signed state + org membership).
  try {
    const installation = await getInstallation(installationId);
    const installLogin = installation?.account?.login ? String(installation.account.login).toLowerCase() : null;
    if (installLogin) {
      const orgLogin = await connectedGithubLogin(payload.organizationId);
      if (orgLogin && orgLogin !== installLogin) {
        logger.warn("oauth.github_app_owner_mismatch", { organizationId: payload.organizationId, installLogin, orgLogin });
        sendHtml(res, 403, renderHtml("GitHub App setup failed", "This installation belongs to a different GitHub account than the one connected to this workspace.", { provider: "GitHub", success: false, nonce: req.cspNonce }));
        return;
      }
    }
  } catch (err) {
    // App-JWT lookup not feasible (App not configured / network) — fall back to
    // the numeric check + signed-state gate above. TODO: once every org has a
    // connected OAuth login on file, make ownership verification mandatory.
    logger.warn("oauth.github_app_verify_skipped", { err: String(err?.message || err) });
  }

  await repo.setGithubInstallation(payload.organizationId, installationId);
  sendHtml(res, 200, renderHtml("GitHub App connected", "Codecanic can now access only the repositories you selected. Your code is never stored.", { provider: "GitHub", success: true, nonce: req.cspNonce }));
}

export default async function handler(req, res) {
  const url = requestUrl(req);
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
    const expose = error?.expose === true;
    const statusCode = expose ? error.statusCode || 400 : 500;
    if (!expose) logger.error("oauth.handler_error", { action, err: error });
    json(res, statusCode, { error: expose ? error.message : "Request failed." });
  }
}
