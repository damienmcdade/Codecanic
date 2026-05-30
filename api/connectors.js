import { createHmac, randomUUID } from "node:crypto";
import { getConnector, json } from "./_lib.js";
import * as repo from "./_repo.js";
import { currentUserContext } from "./_auth.js";
import { decryptSecret } from "./_crypto.js";

function signState(payload) {
  const secret = process.env.CODECANIC_SESSION_SECRET || "codecanic-development-secret-do-not-use-in-prod";
  const value = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${signature}`;
}

const providerGuides = {
  GitHub: {
    type: "oauth",
    accessSummary: "Read your repositories, pull requests, and dependency graph. Open pull requests for approved repairs.",
    scopes: ["repo", "read:org", "workflow"],
    docsUrl: "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
    setupSteps: [
      "Open github.com/settings/developers and click 'New OAuth App'.",
      "Application name: Codecanic. Homepage URL: https://codecanic.app.",
      "Authorization callback URL: paste the redirect URL shown above.",
      "Register the application, then click 'Generate a new client secret'.",
      "Copy Client ID + Client Secret into GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET on your Codecanic deployment."
    ],
    cli: {
      name: "GitHub CLI (gh)",
      homepage: "https://cli.github.com",
      install: {
        mac: "brew install gh",
        windows: "winget install --id GitHub.cli",
        linux: "sudo apt update && sudo apt install gh"
      },
      quickstart: "gh auth login"
    }
  },
  Vercel: {
    type: "oauth",
    accessSummary: "Read deployments, environment variables, and runtime logs for your projects.",
    scopes: [],
    docsUrl: "https://vercel.com/docs/integrations/oauth",
    setupSteps: [
      "Open vercel.com/dashboard → Integrations → Create integration.",
      "Pick your team and name it Codecanic.",
      "Redirect URL: paste the redirect URL shown above. Read scope on Projects and Deployments.",
      "Save the integration and grab Client ID + Client Secret.",
      "Set VERCEL_CLIENT_ID and VERCEL_CLIENT_SECRET on your Codecanic deployment."
    ],
    cli: {
      name: "Vercel CLI",
      homepage: "https://vercel.com/docs/cli",
      install: {
        mac: "npm install -g vercel",
        windows: "npm install -g vercel",
        linux: "npm install -g vercel"
      },
      quickstart: "vercel login"
    }
  },
  GitLab: {
    type: "oauth",
    accessSummary: "Read your repositories, CI pipelines, and issues. Open merge requests for approved repairs.",
    scopes: ["read_repository", "api"],
    docsUrl: "https://docs.gitlab.com/ee/api/oauth2.html",
    setupSteps: [
      "Open gitlab.com/-/profile/applications.",
      "Name: Codecanic.",
      "Redirect URI: paste the redirect URL shown above.",
      "Scopes: tick read_repository and api.",
      "Save, then copy the Application ID + Secret into GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET on your Codecanic deployment."
    ],
    cli: {
      name: "GitLab CLI (glab)",
      homepage: "https://gitlab.com/gitlab-org/cli",
      install: {
        mac: "brew install glab",
        windows: "winget install --id GitLab.GLab",
        linux: "curl -fsSL https://gitlab.com/gitlab-org/cli/-/raw/main/scripts/install.sh | sh"
      },
      quickstart: "glab auth login"
    }
  },
  Bitbucket: {
    type: "oauth",
    accessSummary: "Read your repositories, workspaces, and pull requests. Open pull requests for approved repairs.",
    scopes: ["repository", "account"],
    docsUrl: "https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/",
    setupSteps: [
      "Open your Bitbucket workspace → Settings → OAuth consumers → Add consumer.",
      "Name: Codecanic.",
      "Callback URL: paste the redirect URL shown above.",
      "Permissions: Repository Read, Account Read.",
      "Save and copy the Key + Secret into BITBUCKET_CLIENT_ID and BITBUCKET_CLIENT_SECRET on your Codecanic deployment."
    ],
    cli: null
  },
  Railway: {
    type: "manual",
    accessSummary: "Inspect services, workers, databases, and logs. Uses a personal access token (Railway does not offer OAuth apps).",
    tokenUrl: "https://railway.app/account/tokens",
    tokenInstructions: [
      "Open railway.app and sign in.",
      "Go to Account Settings → Tokens.",
      "Click New Token. Name it 'Codecanic'.",
      "Copy the token and paste it below. Codecanic stores it for this workspace only."
    ],
    cli: {
      name: "Railway CLI",
      homepage: "https://docs.railway.com/develop/cli",
      install: {
        mac: "brew install railway",
        windows: "iwr https://railway.com/install.ps1 | iex",
        linux: "curl -fsSL https://railway.com/install.sh | sh"
      },
      quickstart: "railway login"
    }
  },
  Xcode: {
    type: "manual",
    accessSummary: "Validate iOS build settings and signing. Uses your Apple Developer Team ID — no token required.",
    tokenUrl: "https://developer.apple.com/account",
    tokenInstructions: [
      "Open developer.apple.com and sign in.",
      "Go to Membership Details.",
      "Copy your 10-character Team ID and paste it below."
    ],
    cli: {
      name: "Xcode Command Line Tools",
      homepage: "https://developer.apple.com/xcode/",
      install: {
        mac: "xcode-select --install",
        windows: "Not available — Xcode requires macOS.",
        linux: "Not available — Xcode requires macOS."
      },
      quickstart: "xcodebuild -version"
    }
  }
};

const projectEndpoints = {
  GitHub: {
    url: "https://api.github.com/user/repos?sort=updated&per_page=30",
    auth: (token) => ({ Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" }),
    map: (body) =>
      (Array.isArray(body) ? body : []).map((repo) => ({
        id: String(repo.id),
        name: repo.full_name,
        description: repo.description || repo.private ? "Private" : "Public",
        url: repo.html_url
      }))
  },
  GitLab: {
    url: "https://gitlab.com/api/v4/projects?membership=true&order_by=last_activity_at&per_page=30",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    map: (body) =>
      (Array.isArray(body) ? body : []).map((proj) => ({
        id: String(proj.id),
        name: proj.path_with_namespace,
        description: proj.description || "GitLab project",
        url: proj.web_url
      }))
  },
  Bitbucket: {
    url: "https://api.bitbucket.org/2.0/repositories?role=member&pagelen=30&sort=-updated_on",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    map: (body) =>
      (body?.values || []).map((repo) => ({
        id: repo.uuid,
        name: repo.full_name,
        description: repo.description || "Bitbucket repo",
        url: repo.links?.html?.href || `https://bitbucket.org/${repo.full_name}`
      }))
  },
  Vercel: {
    url: "https://api.vercel.com/v9/projects?limit=30",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    map: (body) =>
      (body?.projects || []).map((project) => ({
        id: project.id,
        name: project.name,
        description: project.framework || "Vercel project",
        url: `https://vercel.com/_dashboard/projects/${project.id}`
      }))
  },
  Railway: {
    url: "https://backboard.railway.com/graphql/v2",
    method: "POST",
    body: JSON.stringify({
      query: "{ projects { edges { node { id name description } } } }"
    }),
    auth: (token) => ({ Authorization: `Bearer ${token}`, "Content-Type": "application/json" }),
    okCheck: (body) => Array.isArray(body?.data?.projects?.edges) && !(body?.errors && body.errors.length),
    map: (body) =>
      (body?.data?.projects?.edges || []).map(({ node }) => ({
        id: node.id,
        name: node.name,
        description: node.description || "Railway project",
        url: `https://railway.app/project/${node.id}`
      }))
  }
};

const verifyEndpoints = {
  GitHub: {
    url: "https://api.github.com/user",
    auth: (token) => ({ Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" }),
    label: (body) => body?.login || body?.name || "GitHub user"
  },
  Vercel: {
    url: "https://api.vercel.com/v2/user",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    label: (body) => body?.user?.username || body?.user?.email || "Vercel user"
  },
  GitLab: {
    url: "https://gitlab.com/api/v4/user",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    label: (body) => body?.username || body?.name || "GitLab user"
  },
  Bitbucket: {
    url: "https://api.bitbucket.org/2.0/user",
    auth: (token) => ({ Authorization: `Bearer ${token}` }),
    label: (body) => body?.username || body?.display_name || "Bitbucket user"
  },
  Railway: {
    url: "https://backboard.railway.com/graphql/v2",
    method: "POST",
    body: JSON.stringify({ query: "{ me { id email } }" }),
    auth: (token) => ({ Authorization: `Bearer ${token}`, "Content-Type": "application/json" }),
    label: (body) => body?.data?.me?.email || "Railway account",
    okCheck: (body) => Boolean(body?.data?.me?.id) && !(body?.errors && body.errors.length)
  }
};

function describeStatus({ name, configured, connection }) {
  const guide = providerGuides[name];
  if (!guide) return { name, configured, status: "unknown" };
  if (connection) {
    return {
      name,
      configured,
      type: guide.type,
      status: "connected",
      connectedAt: connection.updatedAt,
      scope: connection.scope || (guide.scopes ? guide.scopes.join(" ") : null)
    };
  }
  if (!configured) {
    return {
      name,
      configured: false,
      type: guide.type,
      status: "configuration_required"
    };
  }
  return { name, configured, type: guide.type, status: "ready" };
}

async function handleVerify(req, res, url) {
  const name = url.searchParams.get("name");
  const connector = getConnector(name);
  if (!connector) {
    json(res, 404, { error: "Unknown connector" });
    return;
  }
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to verify connections." });
    return;
  }
  const requestedOrg = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization first." });
    return;
  }
  const credential = await repo.findConnectorCred(name, organization.id);
  if (!credential) {
    json(res, 404, { error: `${name} is not connected for this workspace yet.` });
    return;
  }

  const guide = providerGuides[name];
  const plainToken = decryptSecret(credential.accessToken);
  if (guide?.type === "manual" && name === "Xcode") {
    const teamId = plainToken || "";
    const valid = /^[A-Z0-9]{10}$/i.test(teamId);
    json(res, valid ? 200 : 422, {
      provider: name,
      verified: valid,
      account: valid ? `Apple Team ${teamId.toUpperCase()}` : null,
      message: valid
        ? "Team ID format is valid."
        : "Team ID must be 10 alphanumeric characters."
    });
    return;
  }

  const endpoint = verifyEndpoints[name];
  if (!endpoint) {
    json(res, 200, {
      provider: name,
      verified: true,
      account: "Credential stored",
      message: "No live verification available for this provider; credential is saved."
    });
    return;
  }

  try {
    const response = await fetch(endpoint.url, {
      method: endpoint.method || "GET",
      headers: { "User-Agent": "Codecanic-Verify", ...endpoint.auth(plainToken) },
      body: endpoint.body
    });
    const text = await response.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    const okBody = endpoint.okCheck ? endpoint.okCheck(body) : true;
    if (!response.ok || !okBody) {
      json(res, 200, {
        provider: name,
        verified: false,
        account: null,
        statusCode: response.status,
        message:
          body?.errors?.[0]?.message ||
          body?.message ||
          body?.error_description ||
          body?.error ||
          `Provider returned ${response.status}.`
      });
      return;
    }
    json(res, 200, {
      provider: name,
      verified: true,
      account: endpoint.label(body),
      scope: credential.scope || null,
      message: "Live token verified."
    });
  } catch (error) {
    json(res, 200, {
      provider: name,
      verified: false,
      account: null,
      message: error.message || "Could not reach provider."
    });
  }
}

async function handleProjects(req, res, url) {
  const name = url.searchParams.get("name");
  const connector = getConnector(name);
  if (!connector) {
    json(res, 404, { error: "Unknown connector" });
    return;
  }
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in required." });
    return;
  }
  const requestedOrg = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization first." });
    return;
  }
  const credential = await repo.findConnectorCred(name, organization.id);
  if (!credential) {
    json(res, 404, { error: `${name} is not connected for this workspace yet.` });
    return;
  }
  const endpoint = projectEndpoints[name];
  if (!endpoint) {
    json(res, 200, { provider: name, projects: [], message: "QuickConnect project listing is not yet supported for this provider." });
    return;
  }
  try {
    const plainToken = decryptSecret(credential.accessToken);
    const response = await fetch(endpoint.url, {
      method: endpoint.method || "GET",
      headers: { "User-Agent": "Codecanic-Connect", ...endpoint.auth(plainToken) },
      body: endpoint.body
    });
    const text = await response.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    const okBody = endpoint.okCheck ? endpoint.okCheck(body) : true;
    if (!response.ok || !okBody) {
      json(res, 200, {
        provider: name,
        projects: [],
        error:
          body?.errors?.[0]?.message ||
          body?.message ||
          body?.error_description ||
          `Provider returned ${response.status}.`
      });
      return;
    }
    const projects = endpoint.map(body) || [];
    json(res, 200, { provider: name, projects });
  } catch (error) {
    json(res, 200, { provider: name, projects: [], error: error.message || "Could not reach provider." });
  }
}

async function handleStart(req, res, url) {
  const name = url.searchParams.get("name");
  const connector = getConnector(name);
  if (!connector) {
    json(res, 404, { error: "Unknown connector" });
    return;
  }

  const guide = providerGuides[name];
  const isManual = guide?.type === "manual";
  const configured = isManual ? true : Boolean(process.env[connector.env]);
  const clientSecretEnv = connector.env.replace(/_CLIENT_ID$/, "_CLIENT_SECRET");
  const protocol = req.headers["x-forwarded-proto"] || (url.protocol === "https:" ? "https" : "http");
  const host = req.headers.host || "codecanic.local";
  const defaultRedirect = `${protocol}://${host}/api/oauth/callback?provider=${encodeURIComponent(name)}`;
  const redirectUri = process.env.CODECANIC_REDIRECT_URI || defaultRedirect;

  const base = {
    name,
    configured,
    type: guide?.type || "oauth",
    accessSummary: guide?.accessSummary || null,
    scopes: guide?.scopes || null,
    docsUrl: guide?.docsUrl || null,
    tokenUrl: guide?.tokenUrl || null,
    tokenInstructions: guide?.tokenInstructions || null,
    setupSteps: guide?.setupSteps || null,
    cli: guide?.cli || null,
    redirectUri
  };

  if (!configured) {
    json(res, 200, {
      ...base,
      status: "configuration_required",
      requiredEnv: connector.env,
      requiredSecretEnv: guide?.type === "oauth" ? clientSecretEnv : null,
      message: `${name} needs ${connector.env} before authorization can start.`,
      adminInstructions:
        guide?.type === "oauth"
          ? [
              `Register an OAuth app on ${name}.`,
              `Set the redirect URL to ${redirectUri}.`,
              `Add ${connector.env} and ${clientSecretEnv} to your Codecanic environment (Vercel project, Railway service, or .env).`,
              "Redeploy Codecanic so the new variables take effect."
            ]
          : [
              `Add ${connector.env} to your Codecanic environment.`,
              "Redeploy Codecanic so the new variable is loaded."
            ]
    });
    return;
  }

  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to begin authorization." });
    return;
  }

  const requestedOrg = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization first." });
    return;
  }

  if (guide?.type === "manual") {
    const credential = await repo.findConnectorCred(name, organization.id);
    json(res, 200, {
      ...base,
      status: credential ? "connected" : "manual_token_required",
      connected: Boolean(credential),
      connectedAt: credential?.updatedAt || null,
      message: credential
        ? `${name} is connected for this workspace.`
        : `Paste a ${name} token below to connect.`
    });
    return;
  }

  const state = signState({
    nonce: randomUUID(),
    userId: context.user.id,
    organizationId: organization.id,
    provider: name,
    expiresAt: Date.now() + 10 * 60_000
  });

  const authUrl = new URL(connector.authBase);
  authUrl.searchParams.set("client_id", process.env[connector.env]);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("state", state);
  if (connector.scopes) authUrl.searchParams.set("scope", connector.scopes);
  if (name === "GitLab") authUrl.searchParams.set("response_type", "code");

  const credential = await repo.findConnectorCred(name, organization.id);

  json(res, 200, {
    ...base,
    status: credential ? "connected" : "authorization_ready",
    authUrl: authUrl.toString(),
    connected: Boolean(credential),
    connectedAt: credential?.updatedAt || null
  });
}

async function handleList(req, res) {
  const context = await currentUserContext(req);
  const requestedOrg = req.headers["x-codecanic-org"] || null;
  const organization = context
    ? requestedOrg
      ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
      : context.organizations[0]
    : null;
  const orgId = organization?.id || null;
  const connections = orgId ? await repo.credsForOrg(orgId) : [];

  const list = Object.keys(providerGuides).map((name) => {
    const connector = getConnector(name);
    const guide = providerGuides[name];
    const isManual = guide?.type === "manual";
    const configured = isManual ? true : Boolean(connector && process.env[connector.env]);
    const connection = connections.find((entry) => entry.provider === name) || null;
    return describeStatus({ name, configured, connection });
  });

  json(res, 200, { connectors: list });
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.searchParams.get("action");

  try {
    if (action === "verify") return await handleVerify(req, res, url);
    if (action === "list") return await handleList(req, res);
    if (action === "projects") return await handleProjects(req, res, url);
    return await handleStart(req, res, url);
  } catch (error) {
    json(res, 500, { error: error.message || "Connector request failed." });
  }
}
