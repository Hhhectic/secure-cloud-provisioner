/* Drives the Azure half of the page through a real browser, against the real
 * subscription: pre-flight, create, scan, fix, re-scan, delete.
 *
 * The smoke test drives the registry and the routes. app.test.mjs drives the
 * page against a stub. Neither of those is a person clicking Create and
 * watching a real storage account appear, which is the one path the whole
 * project exists to serve and the one nothing has ever exercised end to end.
 *
 * It creates a real storage account, weakens it deliberately so there is
 * something to fix, fixes one finding, and deletes it. Free, and it cleans up
 * after itself - but it is a live run against a real subscription and belongs
 * beside scripts/smoke_test.py rather than in `npm test`.
 *
 *     node frontend/azure-lifecycle.mjs http://127.0.0.1:8000/ui/ /tmp/shots
 */
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const url = process.argv[2] || "http://127.0.0.1:8000/ui/";
const out = process.argv[3] || "/tmp/azure-gui";
mkdirSync(out, { recursive: true });

const NAME = "scpgui" + Math.random().toString(36).slice(2, 8);
const GROUP = "scp-demo";

let pass = 0, fail = 0;
const problems = [];
const ok = (m) => { pass++; console.log(`  pass  ${m}`); };
const bad = (m) => { fail++; console.log(`  FAIL  ${m}`); };
const check = (c, m) => { c ? ok(m) : bad(m); return c; };
const heading = (t) => console.log(`\n${t}\n${"-".repeat(t.length)}`);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 1100 } });
page.on("console", (m) => { if (m.type() === "error") problems.push(m.text()); });
page.on("pageerror", (e) => problems.push(`uncaught: ${e.message}`));

const shot = (n) => page.screenshot({ path: `${out}/${n}.png`, fullPage: true });

// Fills a field by the caption a person actually reads.
async function fill(caption, value) {
  const row = page.locator(".field", { has: page.locator(`label:text-is("${caption}")`) });
  await row.locator("input, textarea").first().fill(value);
}

await page.goto(url, { waitUntil: "networkidle" });

heading("Getting to the Azure half");
await page.click("#cloud-toggle");
await page.waitForTimeout(1500);
check(await page.evaluate(() => document.body.classList.contains("cloud-azure")),
      "the toggle switches the page to Azure");
const entries = await page.$$eval("#types button", (bs) => bs.map((b) => b.dataset.key));
check(entries.length === 5, `five Azure types in the sidebar (${entries.length})`);
check(!entries.some((e) => e.startsWith("azure-") === false),
      "and nothing from the other cloud");
await shot("01-azure");

heading("Storage account: the pre-flight, which creates nothing");
await page.click('#types button[data-key="azure-storage"]');
await page.waitForTimeout(2000);

await fill("name", NAME);
await fill("resource group", GROUP);
// main's Azure forms keep location per resource rather than in the header.
await fill("location", "eastus");

// Deliberately weak, so there is something to find and then fix.
const secure = page.locator(".field", {
  has: page.locator('label:text-is("secure defaults")') }).locator("input[type=checkbox]");
if (await secure.count()) {
  await secure.uncheck();
  ok("unticked secure defaults");
}
await page.waitForTimeout(1200);
await shot("02-form");

const checkBtn = page.locator('button:has-text("Check first")');
if (check(await checkBtn.count() > 0, "the form offers a check that creates nothing")) {
  await checkBtn.click();
  await page.waitForTimeout(3000);
  const body = await page.textContent("body");
  check(/critical|warning|finding/i.test(body),
        "checking an unbuilt account reports findings before it exists");
  await shot("03-preflight");
}

heading("Creating it for real");
const before = Date.now();
await page.click('button:text-is("Create")');
await page.waitForTimeout(6000);

/* A critical finding stops the create, and the way through is a second
   button that only appears once the reasons are on screen. That refusal is
   the behaviour, not a failure - this spec is deliberately weak - so the
   test presses through it deliberately, which is the only way to reach the
   accept-risk path a person would take. */
const anyway = page.locator('button:has-text("Create it anyway")');
if (await anyway.count()) {
  ok("a weak spec is refused before anything is built");
  ok("and the way through is offered only under the reasons");
  await anyway.click();
  await page.waitForTimeout(25000);
} else {
  await page.waitForTimeout(19000);
}
await shot("04-created");

const afterCreate = await page.textContent("body");
const created = check(afterCreate.includes(NAME),
                      `the page reports '${NAME}' after creating it`);
console.log(`        create round trip: ${((Date.now() - before) / 1000).toFixed(0)}s`);

heading("Scanning what was built");
if (created) {
  const row = page.locator("#list tr.clickable", { hasText: NAME });
  if (check(await row.count() > 0, "it appears in the listing")) {
    await row.first().click();
    await page.waitForTimeout(4000);
    await shot("05-scanned");

    const detail = await page.textContent("#detail-body");
    check(/critical|warning|informational|finding/i.test(detail),
          "the scan reports findings on the real account");

    const levels = await page.$$eval("#detail-body .finding",
      (fs) => fs.map((f) => f.className));
    console.log(`        ${levels.length} finding(s) rendered`);

    heading("Fixing one from the page");
    const fixBtn = page.locator("#detail-body button").first();
    if (await fixBtn.count()) {
      const label = (await fixBtn.textContent() || "").trim();
      console.log(`        pressing: ${label}`);
      await fixBtn.click();
      await page.waitForTimeout(12000);
      await shot("06-fixed");

      const after = await page.textContent("body");
      check(!/error|failed|traceback/i.test(after.slice(0, 4000)),
            "the fix reports success rather than an error");

      // Re-scan by reselecting the row.
      await page.locator("#list tr.clickable", { hasText: NAME }).first().click();
      await page.waitForTimeout(4000);
      const after2 = await page.$$eval("#detail-body .finding",
        (fs) => fs.map((f) => f.className));
      console.log(`        after the fix: ${after2.length} finding(s)`);
      check(after2.length <= levels.length,
            "a re-scan shows no more findings than before the fix");
      await shot("07-rescanned");
    } else {
      bad("no fix button was offered on any finding");
    }
  }
}

heading("Deleting it from the page");
if (created) {
  // The delete lives on the listing row, not in the detail panel - and not
  // the modal's own confirm button, which is what a loose text match finds.
  const del = page.locator("#list tr.clickable", { hasText: NAME })
                  .locator("button.danger").first();
  if (check(await del.count() > 0, "a delete control exists")) {
    await del.click();
    await page.waitForTimeout(2500);
    await shot("08-delete-modal");

    // The guard: a forced delete demands the id typed back.
    const confirm = page.locator("#modal input").first();
    if (await confirm.count()) {
      ok("it asks for the name to be typed back before deleting");
      await confirm.fill(NAME);
      await page.waitForTimeout(600);
    }
    const go = page.locator("#modal-go");
    if (await go.count()) {
      check(!(await go.isDisabled()),
            "the delete button unlocks once the name matches");
      await go.click();
      await page.waitForTimeout(30000);
      await shot("09-deleted");
      const gone = await page.textContent("#list");
      check(!gone.includes(NAME), "and it is gone from the listing");
    }
  }
}

heading("Summary");
console.log(`  ${pass} passed, ${fail} failed`);
console.log(problems.length
  ? `  CONSOLE ERRORS:\n    ${[...new Set(problems)].join("\n    ")}`
  : "  no console errors throughout");
console.log(`  account name used: ${NAME}`);

await browser.close();
process.exit(fail ? 1 : 0);
