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

/* Both clouds, because the page shows one at a time.
 *
 * Walking only what is on screen at load covers the AWS half and then reports
 * "no console errors" about an Azure half it never rendered - which is worse
 * than not running, because it reads like coverage. The toggle is read for
 * which clouds exist rather than told, so a third one is walked without this
 * file being reopened. */
const clouds = await page.$$eval("#cloud-toggle .opt",
                                 (os) => os.map((o) => o.dataset.cloud));
console.log("clouds:", clouds.join(", ") || "(only one)");

for (const cloud of clouds.length ? clouds : [null]) {
  if (cloud) {
    // setCloud records the choice as a class on body rather than on the
    // toggle, so that is what says which half is on screen.
    const showing = await page.evaluate(() =>
      document.body.classList.contains("cloud-azure") ? "azure" : "aws");
    if (showing !== cloud) await page.click("#cloud-toggle");
    await page.waitForTimeout(1500);
  }

  /* The page is three tabs now, and #types belongs to two of them.
   *
   * This read #types straight after load. The page opens on the Dashboard,
   * which has no type picker, so it enumerated nothing, walked nothing, and
   * printed "no console errors on any tab of any cloud" about a page it had
   * never opened. A sweep that finds zero things and calls them clean is the
   * exact failure this project spends `unreadable` and *Scan incomplete* on
   * everywhere else, sitting inside the instrument meant to catch it - and its
   * output is indistinguishable from a good run unless somebody notices the
   * list is empty. An empty picker is a reported problem now, not a quiet one.
   *
   * The Dashboard is screenshotted rather than skipped: it scans the whole
   * account on arrival, and a wrong verdict there is the first thing anybody
   * sees. */
  await page.click('#tabs .tab[data-tab="dashboard"]');
  await page.waitForTimeout(4000);
  await page.screenshot({ path: `${out}/${cloud || "all"}-dashboard.png`,
                          fullPage: true });

  for (const pageTab of ["create", "audit"]) {
    await page.click(`#tabs .tab[data-tab="${pageTab}"]`);
    await page.waitForTimeout(1200);

    const tabs = await page.$$eval("#types button", (bs) =>
      bs.map((b) => b.dataset.key));
    console.log(`${cloud || "resources"} / ${pageTab}: ` +
                (tabs.join(", ") || "(nothing listed)"));
    if (!tabs.length) {
      problems.push(`${cloud || "resources"}/${pageTab}: ` +
                    "the type picker listed nothing");
    }

    for (const tab of tabs) {
      await page.click(`#types button[data-key="${tab}"]`);
      await page.waitForTimeout(2500);
      await page.screenshot({ path: `${out}/${pageTab}-${tab}.png`,
                              fullPage: true });

      // Anything the eye would catch: a control with no accessible caption, or
      // a menu whose only entry is the placeholder.
      const empty = await page.$$eval("#create-body select", (ss) =>
        ss.filter((s) => s.options.length <= 1).length);
      if (empty) {
        console.log(`  ${pageTab}/${tab}: ${empty} menu(s) with nothing to choose`);
      }
    }
  }
}

console.log(problems.length
  ? "\nCONSOLE ERRORS:\n  " + [...new Set(problems)].join("\n  ")
  : "\nno console errors on any tab of any cloud");

await browser.close();
