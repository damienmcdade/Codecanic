const plans = {
  Free: { queueDelayMs: 1400, workers: 3, label: "Standard queue", adSupported: true },
  Pro: { queueDelayMs: 500, workers: 8, label: "Priority queue", adSupported: false }
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

export function buildFindings({ sourceUrl = "", scanDepth = "full" }) {
  const normalized = sourceUrl || "Connected workspace";
  const all = [
    {
      id: "secret-env",
      title: "Potential secret exposed in deployment environment",
      type: "security",
      severity: "critical",
      confidence: 91,
      target: "Vercel / Production",
      fix: "Rotate key, move value to managed secret storage, and update deployment references.",
      patchPreview: "Replace plaintext environment value with provider-managed secret reference."
    },
    {
      id: "dep-update",
      title: "Outdated dependency with known vulnerability",
      type: "security",
      severity: "critical",
      confidence: 87,
      target: normalized,
      fix: "Upgrade vulnerable package, regenerate lockfile, and rerun unit checks.",
      patchPreview: "Bump dependency versions and refresh package lock metadata."
    },
    {
      id: "ci-required",
      title: "Main branch can merge without required validation",
      type: "quality",
      severity: "warning",
      confidence: 82,
      target: "GitHub / Branch protection",
      fix: "Require scan, lint, test, and repair validation checks before merge.",
      patchPreview: "Create branch protection policy recommendation."
    },
    {
      id: "ts-strict",
      title: "TypeScript strict mode disabled in shared package",
      type: "quality",
      severity: "warning",
      confidence: 78,
      target: "packages/core/tsconfig.json",
      fix: "Enable strict checks and patch unsafe call sites.",
      patchPreview: "Set strict compiler options and add typed guards."
    },
    {
      id: "slow-build",
      title: "Build cache is not configured for deployment workers",
      type: "performance",
      severity: "warning",
      confidence: 74,
      target: "Railway / worker-service",
      fix: "Add cache-aware install and build steps for repeat deployments.",
      patchPreview: "Add deployment cache hints and stable package manager settings."
    },
    {
      id: "ios-signing",
      title: "iOS build settings missing release signing guardrails",
      type: "quality",
      severity: "warning",
      confidence: 71,
      target: "Xcode / Release configuration",
      fix: "Add release configuration checks and signing validation.",
      patchPreview: "Document signing requirements and fail release builds when profiles are missing."
    }
  ];

  if (scanDepth === "full") return all;
  return all.filter((finding) => finding.type === scanDepth || finding.severity === scanDepth);
}

export function summarize(findings) {
  return {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    warnings: findings.filter((finding) => finding.severity === "warning").length,
    autofixable: findings.filter((finding) => finding.confidence >= 70).length
  };
}
