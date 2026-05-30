const plans = {
  Free: { queueDelayMs: 200, workers: 24, label: "Priority queue" }
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

export async function resolveOrgContext(req) {
  const { currentUserContext } = await import("./_auth.js");
  const context = await currentUserContext(req);
  if (!context) return { authenticated: false };

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const requested =
    req.headers["x-codecanic-org"] ||
    url.searchParams.get("organization") ||
    null;

  let organization = null;
  if (requested) {
    organization =
      context.organizations.find(
        (org) => org.slug === requested || org.id === requested
      ) || null;
  }
  if (!organization) organization = context.organizations[0] || null;
  return { authenticated: true, ...context, organization };
}

export function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request body is too large."));
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
        reject(new Error("Request body must be valid JSON."));
      }
    });
    req.on("error", reject);
  });
}

export function planFor(name) {
  return plans[name] || plans.Free;
}

export function getConnector(name) {
  return connectorConfig[name];
}

// Real scanning lives in ./_scanner.js (scanRepository / scanDirectory).
// The previous hardcoded buildFindings()/summarize() simulation was removed.
