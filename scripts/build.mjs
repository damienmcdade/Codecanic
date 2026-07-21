import { cp, copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { execSync } from "node:child_process";

const staticFiles = [
  "index.html",
  "styles.css",
  "app.js",
  "manifest.webmanifest",
  "sw.js",
  "icon.svg",
  "icon-192.png",
  "icon-512.png",
  "icon-1024.png",
  // SEO + AdSense static files served at the web root. ads.txt authorizes the
  // Google publisher ID (fixes the AdSense "ads.txt not found" status); robots
  // and sitemap make the public content crawlable for review.
  "ads.txt",
  "robots.txt",
  "sitemap.xml",
];

await rm("public", { recursive: true, force: true });
await mkdir("public", { recursive: true });
await mkdir(".codecanic", { recursive: true });

function gitCommit() {
  try {
    return execSync("git rev-parse HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return process.env.RAILWAY_GIT_COMMIT_SHA || process.env.VERCEL_GIT_COMMIT_SHA || process.env.CODECANIC_COMMIT_SHA || "unknown";
  }
}

const builtAt = new Date().toISOString();
const commit = gitCommit();
// Build id used to bust the service-worker cache per deploy.
const buildId = commit !== "unknown" ? commit.slice(0, 12) : String(Date.now());

for (const file of staticFiles) {
  if (file === "sw.js") {
    // Stamp the deploy build id into the service worker's cache name so each
    // deploy evicts the previous deploy's cached bundle.
    const src = await readFile(file, "utf8");
    await writeFile(`public/${file}`, src.replaceAll("__BUILD_ID__", buildId));
  } else {
    await copyFile(file, `public/${file}`);
  }
}

await cp("assets", "public/assets", { recursive: true });

// Standalone /privacy and /terms pages (cleanUrls serves privacy.html at
// /privacy). Content is extracted from the same legalText object app.js renders
// in the in-app legal modal, so the pages can never drift from the app copy.
// App Store review requires the privacy policy at a dedicated, directly
// linkable URL — a modal on the homepage doesn't satisfy that.
{
  const appJs = await readFile("app.js", "utf8");
  const extract = (key) => {
    const m = appJs.match(new RegExp(`${key}: \`([\\s\\S]*?)\`,?\\n(?:  \\w+: \`|};)`));
    if (!m) throw new Error(`legalText.${key} not found in app.js`);
    return m[1];
  };
  const page = (title, body) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title} — Codecanic</title>
  <meta name="description" content="${title} for Codecanic, the AI-assisted repository security scanner." />
  <link rel="icon" href="/icon.svg" type="image/svg+xml" />
  <link rel="stylesheet" href="/styles.css" />
  <style>
    .legal-page { max-width: 860px; margin: 0 auto; padding: 48px 20px 80px; }
    .legal-page h3 { font-size: 1.9rem; margin-bottom: 4px; }
    .legal-page h4 { margin-top: 28px; }
    .legal-page a { color: inherit; }
    .legal-back { display: inline-block; margin-bottom: 24px; color: var(--muted); text-decoration: none; }
    .legal-back:hover { color: var(--ink); }
  </style>
</head>
<body>
  <main class="legal-page">
    <a class="legal-back" href="/">&larr; Back to Codecanic</a>
    ${body}
    <!-- Cross-promotion strip (playbook §14) — the rest of the CyberWave fleet; own link omitted. -->
    <footer class="muted" style="margin-top: 40px; font-size: 12.5px;">
      More from CyberWave Technologies:
      <a href="https://pcsexpress.app" target="_blank" rel="noopener">PCS Express</a> ·
      <a href="https://kinsaga.app" target="_blank" rel="noopener">Kin Saga</a> ·
      <a href="https://storymade.dev" target="_blank" rel="noopener">StoryMade</a> ·
      <a href="https://communitysafe.app" target="_blank" rel="noopener">CommunitySafe</a> ·
      <a href="https://marketscale-ai.vercel.app" target="_blank" rel="noopener">MarketScale AI</a> ·
      <a href="https://apps.apple.com/us/app/id6782158794" target="_blank" rel="noopener">Byte Guardians</a>
    </footer>
</body>
</html>
`;
  await writeFile("public/privacy.html", page("Privacy Policy", extract("privacy")));
  await writeFile("public/terms.html", page("Terms of Service", extract("terms")));
}

// Stamp build info so /api/health reports an accurate, deploy-specific version.
// commit comes from git when available (or a deploy env var); builtAt is always
// accurate, so it answers "did my deploy actually go live?" regardless.
await writeFile("public/version.json", JSON.stringify({ commit, builtAt }, null, 2) + "\n");
await writeFile(".codecanic/build.txt", `Codecanic build ${builtAt}\n`);
console.log(`Codecanic build completed (commit ${commit.slice(0, 12)}, ${builtAt}).`);
