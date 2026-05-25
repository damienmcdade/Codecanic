import { cp, copyFile, mkdir, rm, writeFile } from "node:fs/promises";

const staticFiles = ["index.html", "styles.css", "app.js", "manifest.webmanifest", "sw.js", "icon.svg"];

await rm("public", { recursive: true, force: true });
await mkdir("public", { recursive: true });
await mkdir(".codecanic", { recursive: true });

for (const file of staticFiles) {
  await copyFile(file, `public/${file}`);
}

await cp("assets", "public/assets", { recursive: true });

await writeFile(".codecanic/build.txt", `Codecanic build ${new Date().toISOString()}\n`);
console.log("Codecanic build completed.");
