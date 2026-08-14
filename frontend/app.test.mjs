/* Loads the real page into a DOM and drives it against a fake API.
 *
 * index.html, app.js and keygen.js are loaded exactly as a browser loads
 * them. What is replaced is fetch, so the page talks to a stub that records
 * what it was asked for and answers the way the real API does. The page is
 * therefore tested against its own contract rather than against a rewrite of
 * itself.
 *
 * What is worth testing here is the path from a form to a request body. A bug
 * between the two would create a firewall rule that is not the one somebody
 * chose, which is the failure this whole project exists to prevent and the
 * one no amount of backend testing can catch.
 *
 *     node frontend/app.test.mjs
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const here = dirname(fileURLToPath(import.meta.url));

let failures = 0;
const check = (condition, message) => {
  console.log(`  ${condition ? "pass" : "FAIL"}  ${message}`);
  if (!condition) failures += 1;
  return condition;
};

/* The stub API. Answers enough for the page to boot, and records every
 * request so a test can assert on what was actually sent. */
// The types the stub advertises. Named so the tab-count assertion can be
// derived from it instead of hardcoding a number that goes stale the moment
// somebody adds one.
// provider and short_label are on every entry because the real API puts them
// on every entry. The page shows one cloud at a time and skips anything whose
// provider does not match, so a stub omitting the field would render an empty
// sidebar - and the tests underneath would all fail for that reason rather
// than for theirs.
const STUB_TYPES = [
  { key: "security-group", label: "Security group",
    short_label: "Security group", provider: "aws",
    id_label: "Group ID", read_only: false,
    only_ours_label: "only ones this tool made" },
  // Audited and still filterable, which is the pair that broke the old rule:
  // the page used to disable the box for anything read_only.
  { key: "snapshot", label: "Disk backup",
    short_label: "Disk backup", provider: "aws",
    id_label: "Snapshot ID", read_only: true,
    only_ours_label: "only ones this tool made" },
  // Audited with nothing to narrow by.
  { key: "iam", label: "Account access", short_label: "Account access",
    provider: "aws", id_label: "Account ID",
    read_only: true, only_ours_label: null },
  { key: "alarm", label: "Alarm", short_label: "Alarm", provider: "aws",
    id_label: "Alarm name",
    read_only: false, only_ours_label: "only ones this tool made" },
  // The second cloud, which the page has never been asked about. It reaches
  // these through the registry like anything else, and that is the claim
  // worth testing: nothing in app.js knows the word Azure.
  //
  // read_only was true here long after it stopped being true of the tool, so
  // this file asserted that the page offers no Azure form at all - protecting
  // behaviour the application had already replaced. All five Azure types
  // create, scan, fix and delete now.
  { key: "azure-storage", label: "Azure storage account",
    short_label: "Storage account", provider: "azure",
    id_label: "Account name", read_only: false,
    only_ours_label: "only ones this tool made" },
];


function fakeApi(overrides = {}) {
  const sent = [];

  const routes = {
    "/health": () => ({ status: "ok" }),
    "/resources": () => ({ resources: STUB_TYPES }),
    "/resources/security-group/options": () => ({
      options: {
        vpc_id: [{ value: "vpc-1", label: "demo" }],
        protocol: [{ value: "tcp", label: "TCP" },
                   { value: "udp", label: "UDP" }],
        port: [{ value: "22", label: "22 — SSH" },
               { value: "443", label: "443 — HTTPS" }],
        source: [{ value: "0.0.0.0/0", label: "0.0.0.0/0 — the entire internet" }],
      },
    }),
    // Same path, two shapes: a list on GET and the created resource on POST,
    // which is what the real API does.
    "/resources/security-group": (options) =>
      options.method === "POST"
        ? { resource_type: "security-group", resource_id: "sg-new",
            problems: [], settings: {}, warnings: [],
            counts: { critical: 0, warning: 0, info: 0 } }
        : { resource_type: "security-group", resources: [] },
    "/resources/snapshot": () => ({ resource_type: "snapshot", resources: [] }),
    "/resources/iam": () => ({ resource_type: "iam", resources: [] }),
    "/resources/iam/options": () => ({ options: {} }),
    "/resources/key-pair": () => ({ resource_type: "key-pair", resources: [] }),
    "/resources/network": () => ({ resource_type: "network", resources: [] }),
    "/resources/snapshot/options": () => ({ options: {} }),
    // The unit travels on the metric, because the metric is what decides it.
    "/resources/alarm/options": () => ({
      options: {
        namespace: [
          { value: "AWS/Billing", label: "Account spending ($)" },
          { value: "AWS/EC2", label: "CPU usage (%)" },
        ],
      },
    }),
    "/resources/alarm": () => ({ resource_type: "alarm", resources: [] }),
    "/resources/azure-storage": () => ({
      resource_type: "azure-storage",
      resources: [{ id: "demostorage", name: "demostorage" }],
    }),
    // Shaped like what scanner/azure_storage_rules.py actually returns: no
    // control, because CIS AWS Foundations does not govern Azure.
    "/resources/azure-storage/demostorage": () => ({
      resource_type: "azure-storage", resource_id: "demostorage", settings: {},
      warnings: [{
        level: "critical",
        message: "Containers in 'demostorage' can be opened to anonymous readers.",
        rule_id: "demostorage:public_blob_access",
        resource_id: "demostorage",
        rule: { setting: "public_blob_access" },
        fix: { action: "disable_public_blob_access",
               label: "Stop containers being readable anonymously" },
        control: null,
      }],
      counts: { critical: 1, warning: 0, info: 0 },
    }),
  };

  async function fetchStub(url, options = {}) {
    const path = String(url).replace("..", "").split("?")[0];
    sent.push({ path, options, url: String(url) });

    const handler = overrides[path] || routes[path];
    const body = handler ? handler(options) : {};

    // A handler returning __status is modelling a refusal. The page has a
    // path that only runs on a non-200 - the server declining to build
    // something critical - and a stub that can only answer 200 cannot reach
    // it.
    const { __status: status = 200, ...rest } = body;
    return {
      ok: status < 400,
      status,
      json: async () => (status === 200 ? body : rest),
    };
  }

  return { fetchStub, sent };
}

async function boot(overrides) {
  const { fetchStub, sent } = fakeApi(overrides);

  const dom = new JSDOM(readFileSync(join(here, "index.html"), "utf8"), {
    url: "http://127.0.0.1:8000/ui/",
    runScripts: "outside-only",
  });

  const { window } = dom;
  window.fetch = fetchStub;

  // jsdom implements the DOM, not the whole platform. A real browser has had
  // these for years; keygen.js builds a TextEncoder at load time, so without
  // them the page does not even parse. Node's own implementations are the
  // same specification.
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  for (const [name, value] of Object.entries({
    crypto: globalThis.crypto,
    btoa: globalThis.btoa,
    atob: globalThis.atob,
  })) {
    // crypto is a getter on the jsdom window, so plain assignment is silently
    // discarded and the failure appears much later as a missing subtle.
    Object.defineProperty(window, name, { value, configurable: true,
                                          writable: true });
  }

  // Loaded in the order index.html loads them.
  for (const file of ["keygen.js", "app.js"]) {
    window.eval(readFileSync(join(here, file), "utf8"));
  }

  // Let the boot sequence's promises settle.
  await new Promise((resolve) => setTimeout(resolve, 50));
  return { window, document: window.document, sent };
}

const $ = (doc, id) => doc.getElementById(id);

// --------------------------------------------------------------- the page

console.log("\nBooting");
console.log("-------");

const { window, document, sent } = await boot();

check($(document, "health").textContent === "API up",
      "the health pill reflects a reachable API");
/* The sidebar holds one cloud at a time plus the blueprint, not all fourteen
 * types at once. Counted from the stub rather than written as a number, so
 * adding a type to the stub cannot silently make this assertion about
 * something else. */
const awsTypes = STUB_TYPES.filter((t) => t.provider === "aws");
const azureTypes = STUB_TYPES.filter((t) => t.provider === "azure");

check($(document, "types").children.length === awsTypes.length + 1,
      "the sidebar lists this cloud's types, and the blueprint after them");
check([...$(document, "types").children].every(
        (b) => b.dataset.key === "blueprint"
          || awsTypes.some((t) => t.key === b.dataset.key)),
      "and nothing belonging to the other cloud");
check([...$(document, "types").children]
        .some((b) => b.textContent.includes("audit")),
      "an audited type is labelled as one");
check($(document, "types").lastElementChild.dataset.key === "blueprint",
      "the blueprint sits last, being six resources rather than one type");

// ------------------------------------------- not scanned is not clean

/* "scan each" is off by default, so this is what every list shows on first
 * load. The verdict column printed `worst_level || "clean"`, and worst_level
 * is null both when nothing was found and when nothing was looked for - so an
 * unscanned account with two critical findings sat in the table labelled
 * clean. A tool whose whole purpose is to say what is wrong must not answer
 * that question before it has asked it. */

console.log("\nA row that was never scanned");
console.log("----------------------------");

const { document: scanDoc } = await boot({
  "/resources/security-group": () => ({
    resource_type: "security-group",
    resources: [
      { id: "sg-1", name: "never-scanned", worst_level: null, counts: null },
      { id: "sg-2", name: "scanned-clean", worst_level: null,
        counts: { critical: 0, warning: 0, info: 0 } },
      { id: "sg-3", name: "scanned-bad", worst_level: "critical",
        counts: { critical: 2, warning: 1, info: 0 } },
    ],
  }),
});

const verdicts = [...scanDoc.querySelectorAll("#list tr.clickable")]
  .map((tr) => tr.children[2].textContent);

check(verdicts[0] === "not scanned",
      "a row nobody scanned says so, instead of reporting a verdict");
check(verdicts[1] === "clean",
      "a row that was scanned and came back empty is the one that says clean");
check(verdicts[2] === "critical",
      "and a row with findings says the worst of them");

// ------------------------------------------------------------ the menus

console.log("\nThe create form");
console.log("---------------");

const createBody = $(document, "create-body");
const selects = createBody.querySelectorAll("select");

check(selects.length > 0, "the form asks with menus rather than free text");

const protocolSelect = [...selects].find((s) =>
  [...s.options].some((o) => o.value === "tcp"));

check(protocolSelect,
      "the protocol menu is populated from the API, not hardcoded");
check([...protocolSelect.options].filter((o) => o.textContent === "TCP")
        .length === 1,
      "and lists TCP exactly once");
check(protocolSelect.value === "tcp",
      "with a sensible default already selected");

const portSelect = [...selects].find((s) =>
  [...s.options].some((o) => o.value === "22"));
check([...portSelect.options].some((o) => o.textContent.includes("SSH")),
      "the port menu carries the scanner's own description of each port");

// ------------------------------------------------- form to request body

console.log("\nWhat the form actually sends");
console.log("----------------------------");

function setSelect(select, value) {
  select.value = value;
  select.dispatchEvent(new window.Event("change"));
}

const [nameInput] = createBody.querySelectorAll("input");
nameInput.value = "demo-group";

const vpcSelect = [...selects].find((s) =>
  [...s.options].some((o) => o.value === "vpc-1"));
setSelect(vpcSelect, "vpc-1");
setSelect(portSelect, "22");

const sourceSelect = [...selects].find((s) =>
  [...s.options].some((o) => o.value === "0.0.0.0/0"));
setSelect(sourceSelect, "0.0.0.0/0");

const before = sent.length;
const createButton = [...createBody.querySelectorAll("button")]
  .find((b) => b.textContent === "Create");
createButton.click();
await new Promise((resolve) => setTimeout(resolve, 50));

const post = sent.slice(before).find((r) => r.options.method === "POST");

if (check(Boolean(post), "pressing Create sends a POST")) {
  const body = JSON.parse(post.options.body);

  check(body.name === "demo-group", "the name is carried through");
  check(body.vpc_id === "vpc-1",
        "the chosen network is carried through, not the label");
  check(Array.isArray(body.rules) && body.rules.length === 1,
        "one rule was built from the row");

  const [rule] = body.rules || [{}];
  check(rule.protocol === "tcp", "the rule carries the chosen protocol");
  check(rule.from_port === 22 && rule.to_port === 22,
        "a single port becomes a range of one, not a null");
  check(rule.source === "0.0.0.0/0", "and the chosen source");
  check(typeof rule.from_port === "number",
        "ports are numbers, which is what the API validates");
}

// -------------------------------------------------- an empty rule row

console.log("\nAn empty rule row");
console.log("-----------------");

const { document: doc2, sent: sent2, window: win2 } = await boot();
const body2 = $(doc2, "create-body");
body2.querySelectorAll("input")[0].value = "no-rules";

const before2 = sent2.length;
[...body2.querySelectorAll("button")]
  .find((b) => b.textContent === "Create").click();
await new Promise((resolve) => setTimeout(resolve, 50));

const post2 = sent2.slice(before2).find((r) => r.options.method === "POST");
if (check(Boolean(post2), "a form with an untouched rule row still submits")) {
  const parsed = JSON.parse(post2.options.body);
  check(parsed.rules === undefined,
        "and sends no rules at all rather than one with a null source");
}

// ------------------------------------------------------- audited types

console.log("\nAudited types");
console.log("-------------");

const snapshotTab = [...$(doc2, "types").children]
  .find((b) => b.dataset.key === "snapshot");
snapshotTab.click();
await new Promise((resolve) => setTimeout(resolve, 50));

check($(doc2, "create-body").textContent.includes("audited by this tool"),
      "an audited type offers no create form and says why");
check(!$(doc2, "only-ours").disabled,
      "but its list can still be narrowed, because being unable to change a "
      + "thing does not mean being unable to filter it");

// The pair the old rule got wrong. read_only was the signal for both
// questions, so an audited type that genuinely honours the filter lost it.
const iamTab = [...$(doc2, "types").children].find((b) => b.dataset.key === "iam");
iamTab.click();
await new Promise((resolve) => setTimeout(resolve, 50));

check($(doc2, "only-ours").disabled,
      "a type with nothing to narrow by disables the box");
check($(doc2, "only-ours-label").textContent.includes("nothing to narrow"),
      "and says so rather than leaving a label that means nothing");

// ------------------------------------------- refusing to build something bad

console.log("\nThe pre-flight refusal");
console.log("----------------------");

// The server declines the first POST and accepts the second. Nothing else
// changes, so what is being checked is that the page notices the refusal,
// shows why, and can then proceed on purpose.
let posts = 0;
const { window: win3, document: doc3, sent: sent3 } = await boot({
  "/resources/security-group": (options) => {
    if (options.method !== "POST") {
      return { resource_type: "security-group", resources: [] };
    }
    posts += 1;
    if (posts === 1) {
      return {
        __status: 400,
        detail: {
          message: "Not created. The settings submitted have 1 critical "
                   + "problem, listed below.",
          warnings: [{
            level: "critical",
            message: "Anyone on the internet can reach port 22.",
            rule_id: null, resource_id: null, rule: null, fix: null,
            control: null,
          }],
        },
      };
    }
    return { resource_type: "security-group", resource_id: "sg-anyway",
             problems: [], settings: {}, warnings: [],
             counts: { critical: 0, warning: 0, info: 0 } };
  },
});

const createBody3 = $(doc3, "create-body");
const [nameInput3] = createBody3.querySelectorAll("input");
nameInput3.value = "open-sg";

[...createBody3.querySelectorAll("button")]
  .find((b) => b.textContent === "Create").click();
await new Promise((resolve) => setTimeout(resolve, 50));

const out3 = $(doc3, "create-out");

check(out3.textContent.includes("Not created"),
      "a refused create says so rather than failing silently");
check(out3.textContent.includes("port 22"),
      "and shows the finding that caused it, not just a status code");
check(!out3.textContent.includes("accept_risk"),
      "without naming the query parameter at a person who cannot send one");

const anyway = [...out3.querySelectorAll("button")]
  .find((b) => b.textContent === "Create it anyway");

if (check(Boolean(anyway), "and offers a way through, once the reasons are shown")) {
  const before3 = sent3.length;
  anyway.click();
  await new Promise((resolve) => setTimeout(resolve, 50));

  const retry = sent3.slice(before3).find((r) => r.options.method === "POST");
  if (check(Boolean(retry), "which submits again")) {
    check(retry.url.includes("accept_risk=true"),
          "this time saying the risk was accepted");
    check($(doc3, "create-out").textContent.includes("sg-anyway"),
          "and the resource is created");
  }
}

// ------------------------------------------ a refusal must not outlive the form

/* Two panels used to answer "what would this create?" - the live one above the
 * buttons and a second copy below them - and the lower one was never cleared.
 * Pressing Check with safe settings, then making the form dangerous, left
 * "0 critical" sitting underneath a live panel saying "2 critical", lower down
 * the page where it reads as the conclusion. The check now has one home; what
 * remains below the buttons is the result of acting, and a refusal there is
 * about the spec that was sent. */

console.log("\nA refusal is about the spec that was sent");
console.log("-----------------------------------------");

const { document: staleDoc } = await boot({
  "/resources/security-group": (options) => {
    if (options.method !== "POST") {
      return { resource_type: "security-group", resources: [] };
    }
    return {
      __status: 400,
      detail: {
        message: "Not created. The settings submitted have 1 critical problem.",
        warnings: [{
          level: "critical", message: "Anyone on the internet can reach port 22.",
          rule_id: null, resource_id: null, rule: null, fix: null, control: null,
        }],
      },
    };
  },
});

const staleBody = $(staleDoc, "create-body");
const [staleName] = staleBody.querySelectorAll("input");
staleName.value = "open-sg";
[...staleBody.querySelectorAll("button")]
  .find((b) => b.textContent === "Create").click();
await new Promise((r) => setTimeout(r, 60));

const staleOut = $(staleDoc, "create-out");
check(staleOut.textContent.includes("Not created"), "the refusal is shown");

staleName.value = "open-sg-renamed";
staleName.dispatchEvent(new staleDoc.defaultView.Event("input", { bubbles: true }));
await new Promise((r) => setTimeout(r, 60));

check(staleOut.textContent.trim() === "",
      "and is dropped the moment the form it described changes");

check(!$(staleDoc, "create-out").querySelector("button"),
      "taking its Create it anyway button with it, which was for the old spec");

// ----------------------------------------------------------------- alarms

console.log("\nThe alarm form");
console.log("--------------");

// A type whose fields are not in FIELDS falls back to a lone name box, which
// would submit an alarm with no threshold and be refused for it. This checks
// the page knows the shape of the type rather than merely listing it.
const { document: doc4, sent: sent4 } = await boot({
  "/resources": () => ({
    resources: [
      { key: "alarm", label: "Alarm", id_label: "Alarm name",
        read_only: false },
    ],
  }),
  "/resources/alarm": (options) =>
    options.method === "POST"
      ? { resource_type: "alarm", resource_id: "spend", problems: [],
          settings: {}, warnings: [],
          counts: { critical: 0, warning: 0, info: 0 } }
      : { resource_type: "alarm", resources: [] },
  "/resources/alarm/options": () => ({
    options: {
      namespace: [
        { value: "AWS/Billing", label: "Account spending ($)" },
        { value: "AWS/EC2", label: "CPU usage (%)" },
      ],
    },
  }),
});

const alarmBody = $(doc4, "create-body");
const alarmSelects = [...alarmBody.querySelectorAll("select")];

const fieldNamed = (body, name) => [...body.querySelectorAll(".field")]
  .find((r) => r.querySelector("label")?.textContent === name);

check(alarmSelects.length >= 1,
      "the alarm form offers a metric menu rather than a lone name box");
check(alarmBody.textContent.includes("confirmation link"),
      "and explains that an unconfirmed address receives nothing");

fieldNamed(alarmBody, "name").querySelector("input").value = "spend";
setSelect(alarmSelects.find((s) =>
  [...s.options].some((o) => o.value === "AWS/Billing")), "AWS/Billing");

// Typed, not chosen: any number is legitimate and only the unit is decided
// for you.
fieldNamed(alarmBody, "alert above").querySelector("input").value = "5";

const before4 = sent4.length;
[...alarmBody.querySelectorAll("button")]
  .find((b) => b.textContent === "Create").click();
await new Promise((resolve) => setTimeout(resolve, 50));

const alarmPost = sent4.slice(before4).find((r) => r.options.method === "POST");
if (check(Boolean(alarmPost), "and submits what was chosen")) {
  const spec = JSON.parse(alarmPost.options.body);
  check(spec.namespace === "AWS/Billing", "carrying what to watch");
  check(spec.threshold === "5" || spec.threshold === 5,
        "and the number that sets it off");
  check(spec.notify === true,
        "with notification on by default, since a silent alarm is the "
        + "failure this type exists to prevent");
}

// ------------------------------------------------- the unit is in the label

console.log("\nAlarm thresholds are typed, and the metric names the unit");
console.log("--------------------------------------------------------");

const { document: bandDoc } = await boot();
[...$(bandDoc, "types").children].find((b) => b.dataset.key === "alarm").click();
await new Promise((resolve) => setTimeout(resolve, 50));

const bandForm = $(bandDoc, "create-body");
const fieldRow = (name) => [...bandForm.querySelectorAll(".field")]
  .find((r) => r.querySelector("label")?.textContent === name);

check(Boolean(fieldRow("alert above")),
      "the threshold is captioned as the question it asks, not as its API name");
check(!fieldRow("namespace"),
      "and 'namespace' does not reach the screen, being a CloudWatch word");

const thresholdRow = fieldRow("alert above");
check(!thresholdRow.querySelector("select"),
      "the threshold is typed, because any number is legitimate");
check(!thresholdRow.querySelector(".hint"),
      "with no sentence under it, since the metric already says the unit");

// Real choices only. The blank first row is "— choose —", which would make
// the dash assertion below pass for the wrong reason.
const metricLabels = [...fieldRow("watch").querySelectorAll("option")]
  .filter((o) => o.value && o.value !== "__other__")
  .map((o) => o.textContent);
check(metricLabels.some((l) => l.includes("($)")),
      "spending says its unit in the label");
check(metricLabels.some((l) => l.includes("(%)")),
      "and so does CPU");
check(!metricLabels.some((l) => l.includes("—")),
      "without a dash and an explanation trailing off the end of the menu");

// ------------------------------------------- an acknowledged finding

console.log("\nAn acknowledged finding");
console.log("-----------------------");

const ackWarning = {
  level: "critical", message: "this bucket is public",
  rule_id: "b:public_policy", resource_id: "b", rule: {}, fix: null,
  acknowledged: { reason: "a website, on purpose", by: "richard",
                  on: "2026-08-09", until: "2027-02-09" },
};

const { document: ackDoc } = await boot({
  "/resources/security-group/sg-1": () => ({
    resource_type: "security-group", resource_id: "sg-1", settings: {},
    warnings: [ackWarning],
    counts: { critical: 1, warning: 0, info: 0, acknowledged: 1 },
  }),
  "/resources/security-group": () => ({
    resource_type: "security-group",
    resources: [{ id: "sg-1", name: "demo" }],
  }),
});

await ackDoc.querySelector("#list tr.clickable").click();
await new Promise((r) => setTimeout(r, 60));

const detail = $(ackDoc, "detail-body");
const finding = detail.querySelector(".finding");

check(Boolean(finding), "the finding is rendered at all, not dropped");
check(finding.classList.contains("critical"),
      "and keeps its severity, because an acknowledged critical is still one");
check(finding.classList.contains("acknowledged"),
      "marked as acknowledged so it can be told apart");
check(detail.textContent.includes("richard"),
      "naming who accepted it");
check(detail.textContent.includes("a website, on purpose"),
      "and why");
check(detail.textContent.includes("1 acknowledged"),
      "and the tally says so, rather than quietly subtracting it");

// -------------------------------------------------- the second cloud

/* The page has never been asked about Azure. It reaches it through the
 * registry like anything else, which is the claim worth protecting: nothing
 * in app.js contains the word Azure, so a tab, a scan and a finding for a
 * storage account are all handled by code written for security groups. */

console.log("\nAzure, through the same routes");
console.log("------------------------------");

/* The second cloud is behind the toggle, so getting to it is part of the
 * path being tested. Before the toggle existed all fourteen types sat in one
 * wrapping row and the page offered an AWS region selector and an AWS
 * blueprint above every Azure one. */
check(!document.querySelector('#types button[data-key="azure-storage"]'),
      "the other cloud's types are not in the sidebar to begin with");

$(document, "cloud-toggle").click();
await new Promise((r) => setTimeout(r, 80));

const azTab = document.querySelector('#types button[data-key="azure-storage"]');
check(Boolean(azTab), "switching cloud puts them there");
check(document.body.classList.contains("cloud-azure"),
      "and repaints, so which account is in front of you is not a label to read");
check(!document.querySelector('#types button[data-key="security-group"]'),
      "with the first cloud's types gone rather than merely reordered");
check(!document.querySelector('#types button[data-key="blueprint"]'),
      "and no bastion blueprint, which is an AWS architecture");
check(azTab.textContent.includes("Storage account"),
      "labelled without repeating the cloud the toggle already names");
check(!azTab.textContent.includes("audit"),
      "not labelled audit only, because Azure provisions like anything else");

await azTab.click();
await new Promise((r) => setTimeout(r, 60));

/* The form is the half that broke silently. app.js held a hardcoded field map
 * with no Azure entries, so every Azure type fell back to a name-only form and
 * submitted without the resource group Azure cannot place anything without. A
 * name-only form looks perfectly reasonable on screen. */
const azCreate = $(document, "create-body");
const azCaptions = [...azCreate.querySelectorAll(".field label")]
  .map((l) => l.textContent);
for (const asked of ["name", "resource group", "location", "secure defaults"]) {
  check(azCaptions.includes(asked), `the create form asks for ${asked}`);
}

const azRow = document.querySelector("#list tr.clickable");
if (check(Boolean(azRow), "the account is listed")) {
  await azRow.click();
  await new Promise((r) => setTimeout(r, 60));

  /* The identifier a row carries is the one every per-resource route takes,
   * and the page passes it through untouched. It does not, and must not, know
   * that Azure has a second identifier: the registry hands back the name in
   * `id` precisely so this stays true. It once handed back the full ARM path
   * instead, and detail, fix and delete all 404'd against a resource the page
   * had just created. */
  check(sent.some((r) => r.path === "/resources/azure-storage/demostorage"),
        "and is read back by the identifier the list gave, unaltered");

  const azFinding = $(document, "detail-body").querySelector(".finding");
  check(Boolean(azFinding) && azFinding.classList.contains("critical"),
        "and its finding is rendered at its own severity");
  check(!azFinding.querySelector(".cite"),
        "with no citation, because CIS AWS Foundations does not reach Azure");
}

// ------------------------------------------------ the live pre-flight

/* The check route's own docstring says the form may call it on every
 * keystroke. Until it did, a setting stayed dangerous-but-invisible until
 * somebody thought to press a button, and the whole point is that they
 * should not have to think to press it. */

console.log("\nThe live pre-flight");
console.log("-------------------");

const liveWarning = {
  level: "critical",
  message: "Port 22 is reachable from the entire internet.",
  rule_id: "sgr-1",
  resource_id: null,
  rule: { setting: "open_22" },
  fix: { action: "narrow_to_my_ip", label: "Limit this to my current IP address" },
  control: null,
};

const { document: liveDoc, sent: liveSent } = await boot({
  "/resources/security-group/check": () => ({
    resource_type: "security-group",
    warnings: [liveWarning],
    counts: { critical: 1, warning: 0, info: 0 },
  }),
});

const liveName = $(liveDoc, "create-body")
  .querySelector(".field input:not([type])");

const checksSent = () =>
  liveSent.filter((r) => r.path.endsWith("/check")).length;

check(checksSent() === 0, "nothing is asked before anything is typed");

liveName.value = "demo";
liveName.dispatchEvent(new liveDoc.defaultView.Event("input", { bubbles: true }));
await new Promise((r) => setTimeout(r, 600));

check(checksSent() === 1, "typing a name asks the check route, once");

const livePanel = $(liveDoc, "create-live");
check(livePanel.textContent.includes("1 critical"),
      "and the tally appears without anything being pressed");
check(livePanel.textContent.includes("Nothing has been created"),
      "saying plainly that nothing was made");
check(livePanel.querySelectorAll(".finding").length === 1,
      "with the finding itself rendered");

// The finding carries a fix and a rule_id, which is what the detail view
// needs to offer a button. Here there is nothing to fix: the remedy for a bad
// setting in a form is to change the form, and a Fix button would act on a
// resource that does not exist.
check(livePanel.querySelectorAll("button").length === 0,
      "and no fix button, because the resource does not exist yet");

liveName.value = "";
liveName.dispatchEvent(new liveDoc.defaultView.Event("input", { bubbles: true }));
await new Promise((r) => setTimeout(r, 600));

check(livePanel.children.length === 0,
      "emptying the name clears the panel rather than leaving a stale answer");
check(checksSent() === 1,
      "and asks nothing, a half-typed form being mid-thought rather than wrong");

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
