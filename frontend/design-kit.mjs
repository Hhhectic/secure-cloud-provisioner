/* Builds a design-system kit from the real page.
 *
 * The page is data-driven: index.html is a header and four empty sections, and
 * everything else is drawn by app.js from API responses. A static copy is an
 * empty shell, so this renders the real page in a real browser against a stub
 * API carrying realistic findings, then lifts the rendered subtrees out.
 *
 * Every output file is self-contained - style.css is inlined - so each opens on
 * its own, and carries the @dsCard marker the Design System pane indexes by.
 *
 *     node frontend/design-kit.mjs [frontend-dir] [out-dir]
 *
 * Re-run it after any change to style.css or index.html, so what the design
 * work is looking at is the page as it is now rather than as it was.
 */
import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FRONTEND = process.argv[2] || here;
const OUT = process.argv[3] || join(here, "..", "design-kit");

const css = readFileSync(join(FRONTEND, "style.css"), "utf8");

// ---------------------------------------------------------------- stub API

const PROVIDERS = [
  { key: "aws", label: "AWS", place_label: "Region", place_field: null,
    places: [{ value: "us-east-1", label: "us-east-1 — N. Virginia" },
             { value: "eu-west-2", label: "eu-west-2 — London" }],
    default_place: "us-east-1",
    caution: "This talks to a real AWS account. Creating and deleting here " +
             "does the same thing it does from the command line.",
    blueprints: ["bastion"] },
  { key: "azure", label: "Azure", place_label: "Location", place_field: "location",
    places: [{ value: "eastus", label: "eastus — Virginia" },
             { value: "uksouth", label: "uksouth — London" }],
    default_place: "eastus",
    caution: "This talks to a real Azure subscription. Creating and deleting " +
             "here does the same thing it does from the command line.",
    blueprints: [] },
];

const TYPES = [
  { key: "security-group", label: "Security group", id_label: "Group ID",
    read_only: false, only_ours_label: "only ones this tool made", provider: "aws" },
  { key: "bucket", label: "Storage bucket", id_label: "Bucket name",
    read_only: false, only_ours_label: "only ones this tool made", provider: "aws" },
  { key: "instance", label: "Server", id_label: "Instance ID",
    read_only: false, only_ours_label: "only ones this tool made", provider: "aws" },
  { key: "iam", label: "Account access", id_label: "Account ID",
    read_only: true, only_ours_label: null, provider: "aws" },
  { key: "snapshot", label: "Disk backup", id_label: "Snapshot ID",
    read_only: true, only_ours_label: "only ones this tool made", provider: "aws" },
  { key: "azure-storage", label: "Azure storage account", id_label: "Account name",
    read_only: false, only_ours_label: "only ones this tool made", provider: "azure" },
  { key: "azure-vm", label: "Azure virtual machine", id_label: "Machine name",
    read_only: false, only_ours_label: "only ones this tool made", provider: "azure" },
];

/* One of each severity, plus an acknowledged one - which is the case a
   redesign is most likely to get wrong, because it has to stay legible while
   being visibly quieter. Wording taken from the real scanners. */
const WARNINGS = [
  { level: "critical",
    message: "Port 22 is reachable from the entire internet. That is the " +
             "remote login door for Linux servers, and anyone on the internet " +
             "can knock on it.",
    rule_id: "sgr-0a1b2c3d:open_22", resource_id: "sgr-0a1b2c3d",
    rule: { setting: "open_22" },
    fix: { action: "narrow_to_my_ip", label: "Limit this to my current IP address" },
    control: { framework: "CIS AWS Foundations Benchmark", version: "5.0.0",
               id: "5.3", level: 1 } },
  { level: "warning",
    message: "This bucket accepts plain, unencrypted connections. Anything " +
             "read from or written to it can be watched in transit.",
    rule_id: "scp-demo:no_tls_only", resource_id: "scp-demo",
    rule: { setting: "no_tls_only" },
    fix: { action: "require_tls", label: "Refuse unencrypted connections" },
    control: { framework: "CIS AWS Foundations Benchmark", version: "5.0.0",
               id: "2.1.1", level: 1 } },
  { level: "info",
    message: "This group is not attached to anything. It is harmless while " +
             "that is true, and becomes whatever it says the moment somebody " +
             "attaches it.",
    rule_id: "sg-0eded3eb:unused", resource_id: "sg-0eded3eb",
    rule: { setting: "unused" }, fix: null, control: null },
  { level: "critical",
    message: "Containers in 'scpdemostore' can be opened to anonymous readers.",
    rule_id: "scpdemostore:public_blob_access", resource_id: "scpdemostore",
    rule: { setting: "public_blob_access" },
    fix: { action: "disable_public_blob_access",
           label: "Stop containers being readable anonymously" },
    control: null,
    acknowledged: { by: "gavin", until: "2026-12-01",
                    reason: "Deliberately public marketing site; reviewed "
                            + "and accepted by the group" } },
];

const counts = { critical: 2, warning: 1, info: 1, acknowledged: 1 };

const LISTS = {
  "security-group": [
    { id: "sg-0eded3eb", name: "scp-demo-web", not_ours: false },
    { id: "sg-04547bc7", name: "bastion-sg", not_ours: false },
    { id: "sg-0c4e0ded", name: "someone-elses", not_ours: true },
  ],
  "azure-storage": [{ id: "scpdemostore", name: "scpdemostore", not_ours: false }],
};

const OPTIONS = {
  "security-group": {
    vpc_id: [{ value: "vpc-04051e94", label: "default (vpc-04051e94)" }],
    protocol: [{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }],
    port: [{ value: "22", label: "22 — SSH, the remote login door for Linux servers" },
           { value: "443", label: "443 — HTTPS, an encrypted web server" }],
    source: [{ value: "0.0.0.0/0", label: "0.0.0.0/0 — the entire internet" },
             { value: "10.0.0.0/8", label: "10.0.0.0/8 — private networks only" }],
  },
  "azure-vm": {
    vm_size: [{ value: "Standard_F1als_v7", label: "Standard_F1als_v7 — 1 vCPU" }],
    open_ports: [{ value: "22", label: "22 — SSH, the remote login door for Linux servers" },
                 { value: "443", label: "443 — HTTPS, an encrypted web server" }],
    allowed_source: [{ value: "0.0.0.0/0", label: "0.0.0.0/0 — the entire internet" }],
  },
};

function stubFor(path) {
  if (path === "/health") return { status: "ok" };
  if (path === "/resources") return { resources: TYPES, providers: PROVIDERS };

  const optionsMatch = path.match(/^\/resources\/([\w-]+)\/options$/);
  if (optionsMatch) return { options: OPTIONS[optionsMatch[1]] || {} };

  const detail = path.match(/^\/resources\/([\w-]+)\/([\w.-]+)$/);
  if (detail && !["options", "cleanup", "check"].includes(detail[2])) {
    return {
      resource_type: detail[1], resource_id: detail[2],
      settings: { name: detail[2], vpc_id: "vpc-04051e94" },
      warnings: WARNINGS, counts,
    };
  }

  const list = path.match(/^\/resources\/([\w-]+)$/);
  if (list) return { resource_type: list[1], resources: LISTS[list[1]] || [] };

  return {};
}

// ------------------------------------------------------------------ render

mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1300, height: 1000 } });

await page.route("**/*", async (route) => {
  const url = new URL(route.request().url());
  const p = url.pathname;

  const file = p.match(/\/ui\/([\w.-]+)$/);
  if (file || p === "/ui/" || p === "/ui") {
    const name = file ? file[1] : "index.html";
    const types = { html: "text/html", js: "text/javascript", css: "text/css" };
    return route.fulfill({
      body: readFileSync(join(FRONTEND, name), "utf8"),
      contentType: types[name.split(".").pop()] || "text/plain",
    });
  }

  return route.fulfill({ json: stubFor(p) });
});

await page.goto("http://scp.local/ui/", { waitUntil: "networkidle" });
await page.waitForTimeout(800);

// A resource selected, so the detail panel holds real findings.
await page.click("#list tr.clickable");
await page.waitForTimeout(600);

const page1 = await page.content();

// The Azure half.
await page.click('#cloud button[data-provider="azure"]');
await page.waitForTimeout(1200);
const page2 = await page.content();

// ---------------------------------------------------------------- extract

const parts = await page.evaluate(() => {
  const grab = (sel) => {
    const el = document.querySelector(sel);
    return el ? el.outerHTML : "";
  };
  return {
    header: grab("header"),
    caution: grab("#caution"),
    switch: grab("#cloud"),
    tabs: grab("nav#types"),
  };
});

await page.click('#cloud button[data-provider="aws"]');
await page.waitForTimeout(1000);
await page.click("#list tr.clickable");
await page.waitForTimeout(600);

const awsParts = await page.evaluate(() => {
  const grab = (sel) => {
    const el = document.querySelector(sel);
    return el ? el.outerHTML : "";
  };
  return {
    tabs: grab("nav#types"),
    table: grab("#list table") || grab("#list"),
    findings: [...document.querySelectorAll("#detail-body .finding")]
      .map((f) => f.outerHTML).join("\n"),
    detail: grab("#detail-body"),
    form: grab("#create-body"),
    blueprint: grab("#blueprint-body"),
  };
});

await browser.close();

// ------------------------------------------------------------------ write

function preview({ path, group, name, subtitle, body, note }) {
  const html = `<!-- @dsCard group="${group}" -->
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${name}</title>
<style>
${css}
/* Preview chrome only. Not part of the page - delete when adapting. */
body { padding: 1.5rem; }
.ds-note { max-width: 62rem; margin: 0 0 1.25rem; padding: .6rem .8rem;
           border-left: 3px solid #ccc; background: #fff; color: #444;
           font-size: .84rem; }
.ds-note b { color: #1a1a1a; }
</style>
</head>
<body>
${note ? `<p class="ds-note">${note}</p>` : ""}
${body}
</body>
</html>
`;
  writeFileSync(join(OUT, path), html);
  return { path, group, name, subtitle };
}

mkdirSync(join(OUT, "components"), { recursive: true });
mkdirSync(join(OUT, "pages"), { recursive: true });
mkdirSync(join(OUT, "foundations"), { recursive: true });

const cards = [];

cards.push(preview({
  path: "foundations/severity-colour.html", group: "Foundations",
  name: "Severity colour", subtitle: "critical / warning / info / acknowledged",
  note: "<b>The one rule that is not taste.</b> Colour on this page means " +
        "severity and nothing else. That is why the cloud switch is " +
        "monochrome, and it is what makes red read as red. A brand palette " +
        "here has to argue with this, not quietly replace it.",
  body: awsParts.findings,
}));

cards.push(preview({
  path: "components/cloud-switch.html", group: "Components",
  name: "Cloud switch", subtitle: "AWS / Azure, sliding knob, monochrome",
  note: "Told apart by <b>position and fill</b>, never colour. Built from " +
        "whatever the API declares - it counts positions rather than " +
        "assuming two, so a third cloud must still work.",
  body: parts.switch,
}));

cards.push(preview({
  path: "components/header.html", group: "Components",
  name: "Header bar", subtitle: "title, switch, region/location, health pill",
  note: "The one control that says <b>where</b>. It reads Region on AWS and " +
        "Location on Azure, because those are not the same idea.",
  body: parts.header,
}));

cards.push(preview({
  path: "components/type-tabs.html", group: "Components",
  name: "Resource tabs", subtitle: "one cloud's types, with audit-only tags",
  note: "Nine tabs on AWS, five on Azure. <b>audit only</b> travels beside " +
        "the label rather than inside it, so the resource keeps the name the " +
        "registry gave it.",
  body: awsParts.tabs,
}));

cards.push(preview({
  path: "components/finding.html", group: "Components",
  name: "Finding card", subtitle: "four severities, fix button, CIS citation",
  note: "An <b>acknowledged</b> finding keeps its severity and its place and " +
        "gets quieter - never absent. A suppression that empties the screen " +
        "is how people stop reading the screen.",
  body: awsParts.findings,
}));

cards.push(preview({
  path: "components/resource-table.html", group: "Components",
  name: "Resource list", subtitle: "clickable rows, foreign-resource marking",
  note: "A row marked <b>foreign</b> is something this tool did not create. " +
        "It is the warning before a cascade delete reaches somebody else's " +
        "machine.",
  body: awsParts.table,
}));

cards.push(preview({
  path: "components/create-form.html", group: "Components",
  name: "Create form", subtitle: "captioned rows, menus, rule builder, notes",
  note: "Every control gets a caption above it rather than a placeholder " +
        "inside it, because <b>a placeholder disappears exactly when it is " +
        "needed</b>. Menus come from the API, never from the page.",
  body: awsParts.form,
}));

cards.push(preview({
  path: "components/caution-banner.html", group: "Components",
  name: "Caution banner", subtitle: "per-cloud, names the real account",
  note: "Named per cloud on purpose: <b>a real AWS account</b> was false and " +
        "reassuring on the Azure half, which is the worst thing a warning " +
        "can be.",
  body: parts.caution,
}));

cards.push(preview({
  path: "components/blueprint.html", group: "Components",
  name: "Blueprint panel", subtitle: "bastion architecture, AWS only",
  note: "Hidden entirely on a cloud that has no blueprint, rather than shown " +
        "and refused.",
  body: awsParts.blueprint,
}));

function fullPage(path, group, name, subtitle, note, html) {
  const withCss = html
    .replace(/<link rel="stylesheet" href="style.css">/,
             `<style>\n${css}\n</style>`)
    // Scripts would re-fetch an API that is not there and blank the page.
    .replace(/<script src="[^"]*"><\/script>/g, "")
    .replace(/<body>/,
             `<body>\n<p class="ds-note" style="max-width:62rem;margin:0 0 1.25rem;` +
             `padding:.6rem .8rem;border-left:3px solid #ccc;background:#fff;` +
             `color:#444;font-size:.84rem">${note}</p>`)
    .replace(/<head>/, `<head>\n<!-- @dsCard group="${group}" -->`);
  writeFileSync(join(OUT, path), `<!-- @dsCard group="${group}" -->\n${withCss}`);
  cards.push({ path, group, name, subtitle });
}

fullPage("pages/aws.html", "Pages", "AWS page", "nine types, blueprint shown",
         "Fully rendered, scripts removed. <b>Static</b> - the switch and tabs " +
         "will not respond; this is for looking at, not clicking.", page1);
fullPage("pages/azure.html", "Pages", "Azure page", "five types, no blueprint",
         "The same page, other cloud. Note <b>Location</b> in the header and " +
         "the absent blueprint panel.", page2);

writeFileSync(join(OUT, "cards.json"), JSON.stringify(cards, null, 2));
console.log(`wrote ${cards.length} previews to ${OUT}`);
for (const c of cards) console.log(`  ${c.group.padEnd(12)} ${c.path}`);
