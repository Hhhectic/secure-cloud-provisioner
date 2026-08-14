/* Drives the real page in a real browser against the real API.
 *
 * jsdom proves the logic and a stub always answers. This is the other half:
 * real latency, real error shapes, and whether anything is actually reachable
 * on screen. Console errors are collected because the class of bug that makes
 * a button silently do nothing leaves no other trace.
 *
 *     node frontend/browse.mjs <url> <outdir>
 */
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const url = process.argv[2] || "http://127.0.0.1:8000/ui/";
const out = process.argv[3] || "/tmp/scp-shots";
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1300, height: 1000 } });

const problems = [];
page.on("console", (m) => { if (m.type() === "error") problems.push(m.text()); });
page.on("pageerror", (e) => problems.push(`uncaught: ${e.message}`));
page.on("requestfailed", (r) =>
  problems.push(`request failed: ${r.url()} ${r.failure()?.errorText}`));

await page.goto(url, { waitUntil: "networkidle" });

const tabs = await page.$$eval("#types button", (bs) =>
  bs.map((b) => b.dataset.key));
console.log("tabs:", tabs.join(", "));

for (const tab of tabs) {
  await page.click(`#types button[data-key="${tab}"]`);
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `${out}/${tab}.png`, fullPage: true });

  // Anything the eye would catch: a control with no accessible caption, or a
  // menu whose only entry is the placeholder.
  const empty = await page.$$eval("#create-body select", (ss) =>
    ss.filter((s) => s.options.length <= 1).length);
  if (empty) console.log(`  ${tab}: ${empty} menu(s) with nothing to choose`);
}

console.log(problems.length
  ? "\nCONSOLE ERRORS:\n  " + [...new Set(problems)].join("\n  ")
  : "\nno console errors on any tab");

await browser.close();
