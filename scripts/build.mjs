import { cp, copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { execSync } from "node:child_process";

const staticFiles = ["index.html", "styles.css", "app.js", "manifest.webmanifest", "sw.js", "icon.svg"];

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

// Stamp build info so /api/health reports an accurate, deploy-specific version.
// commit comes from git when available (or a deploy env var); builtAt is always
// accurate, so it answers "did my deploy actually go live?" regardless.
await writeFile("public/version.json", JSON.stringify({ commit, builtAt }, null, 2) + "\n");
await writeFile(".codecanic/build.txt", `Codecanic build ${builtAt}\n`);
console.log(`Codecanic build completed (commit ${commit.slice(0, 12)}, ${builtAt}).`);
