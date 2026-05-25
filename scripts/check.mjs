import { access, readFile } from "node:fs/promises";

const requiredFiles = [
  "index.html",
  "styles.css",
  "app.js",
  "manifest.webmanifest",
  "sw.js",
  "vercel.json",
  "railway.json",
  "README.md"
];

for (const file of requiredFiles) {
  await access(file);
}

const html = await readFile("index.html", "utf8");
for (const marker of ["Codecanic", "Connectors", "Findings report", "Tiered repair speed"]) {
  if (!html.includes(marker)) {
    throw new Error(`Missing expected UI marker: ${marker}`);
  }
}

console.log("Codecanic project check passed.");
