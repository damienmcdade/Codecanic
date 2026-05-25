import { mkdir, writeFile } from "node:fs/promises";

await mkdir(".codecanic", { recursive: true });
await writeFile(".codecanic/build.txt", `Codecanic build ${new Date().toISOString()}\n`);
console.log("Codecanic build completed.");
