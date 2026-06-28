// Generates App Store screenshots for the Codecanic iOS app at 6.9" device size
// (1290 x 2796), rendering the LIVE site with the native iOS user-agent marker
// ("CodecaniciOS") so the page enters native mode: no ads, no cookie banner —
// exactly what App Review sees on an iPhone 17 Pro Max.
import puppeteer from "puppeteer";
import { mkdir } from "node:fs/promises";

const OUT = process.env.SHOT_OUT || `${process.env.HOME}/Desktop/Codecanic-Screenshots/iPhone-6.9`;
const BASE = process.env.SHOT_URL || "https://codecanic.app";

await mkdir(OUT, { recursive: true });

const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox"] });
const page = await browser.newPage();

const baseUA = await browser.userAgent();
await page.setUserAgent(baseUA.replace(/Headless/gi, "") + " CodecaniciOS/1.1.0");
// 430 x 932 CSS px @ 3x = 1290 x 2796 device px (Apple 6.9" requirement).
await page.setViewport({ width: 430, height: 932, deviceScaleFactor: 3 });

await page.goto(BASE, { waitUntil: "networkidle2", timeout: 60000 });
await new Promise((r) => setTimeout(r, 1500));

// Sanity: confirm native mode engaged (ads/banner suppressed).
const native = await page.evaluate(() => document.body.classList.contains("is-native"));
console.log("native mode (is-native on body):", native);
const adsVisible = await page.evaluate(() =>
  [...document.querySelectorAll(".ad-slot")].some((el) => el.offsetParent !== null)
);
console.log("any ad-slot visible:", adsVisible);

async function shotSection(file, selector) {
  await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (el) el.scrollIntoView({ block: "start", behavior: "instant" });
    else window.scrollTo(0, 0);
  }, selector);
  await new Promise((r) => setTimeout(r, 700));
  await page.screenshot({ path: `${OUT}/${file}` });
  console.log("saved", file);
}

await shotSection("01-overview.png", "#overview");
await shotSection("02-connectors.png", "#connectors");
await shotSection("03-scan.png", "#scan");
await shotSection("04-repairs.png", "#repairs");
await shotSection("05-how-it-works.png", "#how-it-works");
await shotSection("06-what-we-scan.png", "#what-we-scan");

// Account screen — reveal the signed-in account card (real app UI) so the
// "Delete account" control is visible, documenting account deletion (5.1.1(v)).
// Reload fresh and reveal+frame in one shot: the app re-renders on a delay and
// would otherwise re-hide the signed-in section.
await page.goto(BASE, { waitUntil: "networkidle2", timeout: 60000 });
await new Promise((r) => setTimeout(r, 2200));
await page.evaluate(() => {
  // Inline !important survives the app re-render, which only toggles the
  // `hidden` attribute ([hidden]{display:none}).
  const guest = document.querySelector(".account-signed-out");
  const signed = document.querySelector(".account-signed-in");
  if (guest) guest.style.setProperty("display", "none", "important");
  if (signed) signed.style.setProperty("display", "block", "important");
  const name = document.querySelector("#account-name");
  const email = document.querySelector("#account-email");
  if (name) name.textContent = "Demo Engineer";
  if (email) email.textContent = "demo@codecanic.app";
  window.scrollTo(0, 0);
});
await new Promise((r) => setTimeout(r, 500));
await page.screenshot({ path: `${OUT}/07-account-delete.png` });
console.log("saved 07-account-delete.png");

// Open the actual Delete-account confirmation modal for the review screenshot.
await page.evaluate(() => {
  const btn = document.querySelector("#delete-account-button");
  if (btn) btn.click();
});
await new Promise((r) => setTimeout(r, 700));
await page.screenshot({ path: `${OUT}/08-delete-confirm.png` });
console.log("saved 08-delete-confirm.png");

await browser.close();
console.log("Done. Output:", OUT);
