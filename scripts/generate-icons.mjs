import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import sharp from "sharp";

const root = path.resolve(import.meta.dirname, "..");

const fullIconSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="Codecanic logo">
  <defs>
    <linearGradient id="bg" x1="64" y1="24" x2="448" y2="488" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0B1220"/>
      <stop offset="0.52" stop-color="#111827"/>
      <stop offset="1" stop-color="#020617"/>
    </linearGradient>
    <linearGradient id="teal" x1="126" y1="92" x2="404" y2="420" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#67E8F9"/>
      <stop offset="0.5" stop-color="#14B8A6"/>
      <stop offset="1" stop-color="#0F766E"/>
    </linearGradient>
    <linearGradient id="spark" x1="136" y1="144" x2="390" y2="382" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#FDE68A"/>
      <stop offset="1" stop-color="#F97316"/>
    </linearGradient>
    <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="10" result="blur"/>
      <feColorMatrix in="blur" type="matrix" values="0 0 0 0 0.08 0 0 0 0 0.72 0 0 0 0 0.65 0 0 0 0.75 0"/>
      <feMerge>
        <feMergeNode/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  <rect width="512" height="512" rx="96" fill="url(#bg)"/>
  <path d="M74 378h364" stroke="#172554" stroke-width="18" stroke-linecap="round" opacity="0.7"/>
  <path d="M96 142h320M96 256h320M96 370h320M142 96v320M256 96v320M370 96v320" stroke="#1E293B" stroke-width="4" opacity="0.55"/>
  <circle cx="386" cy="118" r="44" fill="#0F172A" stroke="#334155" stroke-width="6"/>
  <path d="M372 118l14 14 28-32" fill="none" stroke="#34D399" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M347 166c-29-30-64-45-105-45-43 0-79 14-107 43-29 29-43 64-43 106 0 43 14 78 43 107 28 29 64 43 107 43 41 0 76-15 105-45l-45-48c-16 16-35 24-58 24-22 0-41-8-56-23-15-16-23-35-23-58s8-42 23-58c15-15 34-23 56-23 23 0 42 8 58 24l45-47Z" fill="#F8FAFC"/>
  <path d="M349 270c0 58-47 105-105 105" fill="none" stroke="url(#teal)" stroke-width="30" stroke-linecap="round" filter="url(#glow)"/>
  <path d="M291 154l-44 92h64l-90 140 26-104h-62l54-128h52Z" fill="url(#spark)"/>
  <path d="M126 438h260" stroke="#14B8A6" stroke-width="10" stroke-linecap="round" opacity="0.8"/>
  <circle cx="116" cy="438" r="8" fill="#67E8F9"/>
  <circle cx="402" cy="438" r="8" fill="#F97316"/>
</svg>`;

const foregroundSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="teal" x1="126" y1="92" x2="404" y2="420" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#67E8F9"/>
      <stop offset="0.5" stop-color="#14B8A6"/>
      <stop offset="1" stop-color="#0F766E"/>
    </linearGradient>
    <linearGradient id="spark" x1="136" y1="144" x2="390" y2="382" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#FDE68A"/>
      <stop offset="1" stop-color="#F97316"/>
    </linearGradient>
  </defs>
  <path d="M347 166c-29-30-64-45-105-45-43 0-79 14-107 43-29 29-43 64-43 106 0 43 14 78 43 107 28 29 64 43 107 43 41 0 76-15 105-45l-45-48c-16 16-35 24-58 24-22 0-41-8-56-23-15-16-23-35-23-58s8-42 23-58c15-15 34-23 56-23 23 0 42 8 58 24l45-47Z" fill="#F8FAFC"/>
  <path d="M349 270c0 58-47 105-105 105" fill="none" stroke="url(#teal)" stroke-width="30" stroke-linecap="round"/>
  <path d="M291 154l-44 92h64l-90 140 26-104h-62l54-128h52Z" fill="url(#spark)"/>
</svg>`;

async function ensureDir(file) {
  await mkdir(path.dirname(file), { recursive: true });
}

async function png(svg, file, size, flatten = true) {
  await ensureDir(file);
  let image = sharp(Buffer.from(svg)).resize(size, size, { fit: "cover" });
  if (flatten) image = image.flatten({ background: "#08111F" });
  await image.png().toFile(file);
}

const webSizes = [192, 512, 1024];

await writeFile(path.join(root, "icon.svg"), fullIconSvg);
for (const size of webSizes) {
  await png(fullIconSvg, path.join(root, `icon-${size}.png`), size);
}

await png(fullIconSvg, path.join(root, "ios/Codecanic/Codecanic/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png"), 1024);
await writeFile(
  path.join(root, "ios/Codecanic/Codecanic/Assets.xcassets/AppIcon.appiconset/Contents.json"),
  JSON.stringify(
    {
      images: [
        {
          filename: "AppIcon-1024.png",
          idiom: "universal",
          platform: "ios",
          size: "1024x1024",
        },
      ],
      info: { author: "xcode", version: 1 },
    },
    null,
    2,
  ) + "\n",
);

const android = [
  ["mipmap-mdpi", 48, 108],
  ["mipmap-hdpi", 72, 162],
  ["mipmap-xhdpi", 96, 216],
  ["mipmap-xxhdpi", 144, 324],
  ["mipmap-xxxhdpi", 192, 432],
];

for (const [dir, launcherSize, foregroundSize] of android) {
  const base = path.join(root, "android/app/src/main/res", dir);
  await png(fullIconSvg, path.join(base, "ic_launcher.png"), launcherSize);
  await png(fullIconSvg, path.join(base, "ic_launcher_round.png"), launcherSize);
  await png(foregroundSvg, path.join(base, "ic_launcher_foreground.png"), foregroundSize, false);
}

console.log("Codecanic icon assets regenerated.");
