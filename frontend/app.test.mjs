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
    // resource_group and location are on the row because _az_summary puts them
    // there. An Azure name is only unique inside its resource group, so a row
    // without one is an identifier that cannot be resolved by a reader.
    "/resources/azure-storage": () => ({
      resource_type: "azure-storage",
      resources: [{ id: "demostorage", name: "demostorage",
                    resource_group: "scp-demo", location: "eastus" }],
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

    // The full url as well as the options, because with_scan travels in the
    // query string and a stub that cannot see it cannot model the one
    // difference that matters: a list answers with counts when it was asked
    // to scan and without them when it was not.
    const handler = overrides[path] || routes[path];
    const body = handler ? handler(options, String(url)) : {};

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

async function boot(overrides, tab) {
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

  /* The page opens on the Dashboard, which has no resource picker and no
     forms, so almost every test here has to say which job it is testing
     first. `audit` is the default because it is the tab that lists every
     type - the audited ones included - and because the list and the detail
     panel are the two things most of these assertions are about.

     Deliberately a click rather than reaching into state: the tab bar is part
     of what is being tested, and a test that bypassed it would keep passing
     if the buttons stopped working. */
  const wanted = tab || "audit";
  const button = window.document.querySelector(`.tab[data-tab="${wanted}"]`);
  // Only when it is not already the open one. Clicking the active tab is a
  // legitimate way to reload it, so doing it here would make every dashboard
  // test count two scans where a browser does one.
  if (!button.classList.contains("active")) {
    button.click();
    await new Promise((resolve) => setTimeout(resolve, 60));
  }
  return { window, document: window.document, sent };
}

const $ = (doc, id) => doc.getElementById(id);

// --------------------------------------------------------------- the page

console.log("\nBooting");
console.log("-------");

/* Most of this file drives forms, so the shared page sits on Create. The page
 * itself opens on the Dashboard, which has no picker and no forms. */
const { window, document, sent } = await boot(undefined, "create");

check($(document, "health").textContent === "API up",
      "the health pill reflects a reachable API");

const awsTypes = STUB_TYPES.filter((t) => t.provider === "aws");
const azureTypes = STUB_TYPES.filter((t) => t.provider === "azure");
const creatable = awsTypes.filter((t) => !t.read_only);

/* Three jobs above fourteen nouns. "Resources" was one list holding the form
 * you fill in to make something and the report you read to find out what is
 * wrong with it, which are different jobs done at different times.
 *
 * The two sidebars are asserted separately because the split is the point: a
 * type that cannot be created has no business on Create, where its form would
 * be an advertised endpoint that always answers 405. */
check($(document, "tabs").children.length === 3,
      "three tabs: dashboard, create, audit");
check($(document, "dashboard").classList.contains("hidden"),
      "the dashboard is put away while Create is open");

check($(document, "types").children.length === creatable.length + 1,
      "Create lists only the types that can be created, and the blueprint");
check(![...$(document, "types").children]
        .some((b) => b.textContent.includes("audit")),
      "so nothing audit-only is offered a form that would always be refused");
check([...$(document, "types").children].every(
        (b) => b.dataset.key === "blueprint"
          || awsTypes.some((t) => t.key === b.dataset.key)),
      "and nothing belonging to the other cloud");
check($(document, "types").lastElementChild.dataset.key === "blueprint",
      "the blueprint sits last, being six resources rather than one type");

const { document: auditDoc } = await boot(undefined, "audit");
check($(auditDoc, "types").children.length === awsTypes.length,
      "Audit lists every type, because looking at one you made and one you " +
      "did not is the same activity");
/* The sidebar used to tag audited types with the word "audit". It said the
   same thing as the heading above it and the tab above that, and the fact it
   was really carrying - "this one cannot be created" - is now said by the
   type's absence from Create. What being read-only actually costs you here is
   a Delete button and a cleanup, and the badge in the listing header says so
   where that applies; it is checked in the audited-types block below. */
check(![...$(auditDoc, "types").children]
        .some((b) => b.textContent.includes("audit")),
      "the sidebar does not repeat what the tab and the heading already say");
check(![...$(auditDoc, "types").children]
        .some((b) => b.dataset.key === "blueprint"),
      "and the blueprint is not there, being a way of making things");
check($(auditDoc, "create").classList.contains("hidden"),
      "the create form is put away while Audit is open");

// ------------------------------------------- not scanned is not clean

/* "scan each" is off by default, so this is what every list shows on first
 * load. The verdict column printed `worst_level || "clean"`, and worst_level
 * is null both when nothing was found and when nothing was looked for - so an
 * unscanned account with two critical findings sat in the table labelled
 * clean. A tool whose whole purpose is to say what is wrong must not answer
 * that question before it has asked it. */

console.log("\nA row that was never scanned");
console.log("----------------------------");

/* Starting a scan and reading its answers are different acts in different
   places now: the Dashboard runs it, the Audit list shows what it found. So
   this drives the real path - list, scan, list again - rather than handing
   the page counts in a list response it no longer reads. */
const scanStub = {
  // An unforced delete that succeeds, so the invalidation below is reached.
  "/resources/security-group/sg-2": () => ({ ok: true, message: "Deleted sg-2." }),
  "/resources/security-group": (options, url) => {
    const scanned = url.includes("with_scan=true");
    const row = (id, name, counts) =>
      ({ id, name, worst_level: null, counts: scanned ? counts : null });
    return {
      resource_type: "security-group",
      resources: [
        row("sg-2", "scanned-clean", { critical: 0, warning: 0, info: 0 }),
        row("sg-3", "scanned-bad", { critical: 2, warning: 1, info: 0 }),
      ],
    };
  },
};

const { document: scanDoc, sent: scanSent } = await boot(scanStub, "audit");

const verdictsNow = () => [...scanDoc.querySelectorAll("#list tr.clickable")]
  .map((tr) => tr.children[2].textContent);

/* The dashboard scans itself on load - measured at 3.4 seconds for a whole
   AWS account, because the types are asked in parallel - so by the time
   anybody reaches this tab the verdicts are usually there. What is asserted
   is that they came from a scan and that the list did not run one. */
check(scanSent.some((r) => r.url.includes("with_scan=true")),
      "the dashboard scans on load rather than waiting to be asked");
check(!scanSent.some((r) => r.url.includes("with_scan=true")
                         && r.url.includes("only_ours=true")),
      "and does it over everything, not only what this tool made");

check(verdictsNow()[0] === "clean",
      "a row that was scanned and came back empty is the one that says clean");
check(verdictsNow()[1] === "critical",
      "and a row with findings says the worst of them");
check(scanDoc.querySelector(".scan-note").textContent.includes("Verdicts from the scan at"),
      "with the time it was taken, so a verdict carries its own provenance");

/* A verdict about a resource that has since changed is not merely old: it is
   wrong, and wrong while carrying a timestamp that makes it look checked. So
   anything that changes a type throws that type's verdicts away rather than
   showing them next to a resource they no longer describe. */
scanDoc.querySelector("#list tr.clickable button.danger").click();
await new Promise((r) => setTimeout(r, 150));

check(verdictsNow().every((v) => v === "not scanned"),
      "deleting something forgets that type's verdicts rather than ageing them");
check(!scanDoc.querySelector(".scan-note").textContent.includes("Verdicts from"),
      "and the list stops claiming a scan it can no longer stand behind");
check(Boolean(scanDoc.querySelector(".scan-note button.link")),
      "saying instead where a fresh one is started, which is one place");

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

const { document: doc2, sent: sent2, window: win2 } = await boot(undefined, "create");
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

/* An audited type used to be reached from the same list as every other one
   and answered with a create panel explaining that it had nothing to create.
   The tab split says the same thing earlier and without the panel: it is not
   offered on Create at all. What still has to hold is that it is a full
   citizen of Audit, filter and all. */
const auditedDoc = (await boot(undefined, "audit")).document;

check(![...$(document, "types").children]
        .some((b) => b.dataset.key === "snapshot"),
      "an audited type is absent from Create rather than explaining itself there");

const snapshotTab = [...$(auditedDoc, "types").children]
  .find((b) => b.dataset.key === "snapshot");
snapshotTab.click();
await new Promise((resolve) => setTimeout(resolve, 50));

check(!$(auditedDoc, "audit-badge").classList.contains("hidden"),
      "and is marked as audit-only where it does appear");

/* "only ones this tool made" used to live here, on by default, and the two
   assertions that stood in its place were about which types could enable it.
   It is gone: with it on, this tab answered a narrower question than the
   Dashboard beside it - whose counts have always been every resource - so the
   same account read as two different accounts depending which tab you were
   on. An audit that hides what the tool did not create also has the default
   backwards, because the resources somebody else made are the ones nobody has
   looked at. */
check(!$(auditedDoc, "listing").querySelector('input[type="checkbox"]'),
      "and the list offers no filter that would answer a narrower question "
      + "than the dashboard");
check(scanSent.every((r) => !r.url.includes("only_ours=true")),
      "nothing this page asks for is narrowed to what it made");

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
}, "create");

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
}, "create");

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
}, "create");

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

const { document: bandDoc } = await boot(undefined, "create");
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

const { document: ackDoc, sent: ackFindingSent } = await boot({
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
/* The counts used to be one sentence - "1 critical, 0 warning, 0
   informational — 1 acknowledged" - and are four tallies now, so this asserts
   the structure rather than the wording. What has to stay true is the same
   thing it always was: the acknowledged count sits beside the severities and
   is never subtracted from them. */
const accepted = detail.querySelector(".tally.accepted");
check(Boolean(accepted) && accepted.querySelector(".n").textContent === "1",
      "and the tally says so, rather than quietly subtracting it");
check(detail.querySelector(".tally.critical .n").textContent === "1",
      "the critical it was still counts as critical");

/* Undoing it sits with the decision it undoes. There is no form and no
   confirmation step, because every guard on accepting a finding exists to make
   *quietening* one expensive - and this only makes one louder, back to the
   state the tool starts in. confirm is still sent, filled in from the finding
   the button belongs to, so a request cannot be cross-wired to another rule. */
const undo = [...finding.querySelectorAll("button")]
  .find((b) => /stop accepting/i.test(b.textContent));
if (check(Boolean(undo), "an accepted finding offers a way to stop accepting it")) {
  const beforeUndo = ackFindingSent.length;
  undo.click();
  await new Promise((r) => setTimeout(r, 60));

  const call = ackFindingSent.slice(beforeUndo)
    .find((r) => r.options.method === "DELETE");
  if (check(Boolean(call), "which asks the server to remove it")) {
    check(call.url.includes("/acknowledgements/"),
          "against the acknowledgement rather than the resource");
    check(call.url.includes("confirm=b%3Apublic_policy"),
          "naming the rule twice, as the write path also demands");
  }
}

/* A level with nothing in it stays on screen. A row that silently omits the
   level somebody was looking for cannot be told from one that never checked,
   which is the way this tool can actively mislead. */
const emptyWarning = detail.querySelector(".tally.warning");
check(Boolean(emptyWarning) && emptyWarning.classList.contains("empty"),
      "a level with nothing in it is drawn as the non-event it is, not dropped");

/* Each level is a drawer and its count is the handle. Showing every finding
   at once is a wall and a wall gets skimmed - but the rule this page follows
   everywhere else is that a finding is made quieter and never absent, and one
   nobody thought to expand has been made absent whatever the count says. So
   criticals arrive open and nothing else does. */
check(detail.querySelector("#findings-critical").classList.contains("open"),
      "the criticals are open on arrival, never behind a click");
check(detail.querySelector(".tally.critical").getAttribute("aria-expanded") === "true",
      "and say so, for anything not reading the colours");
check(!detail.querySelector("#findings-info").classList.contains("open"),
      "the quieter levels start folded, which is what makes criticals findable");

check(emptyWarning.disabled,
      "a level with nothing behind it is not a button that does nothing");

/* Accepted counts findings that are still listed under their own severity, so
   a fourth drawer would either list them twice or subtract them from the
   level they belong to - and subtracting is the suppression this refuses. */
check(detail.querySelector(".tally.accepted").tagName === "DIV",
      "accepted is a count rather than a drawer, its findings being listed already");

// The interaction itself, which is the whole feature. Driven on critical
// because it is the level this stub actually has a finding at - clicking one
// of the empty ones would pass for the wrong reason, since a disabled button
// also leaves its panel shut.
const critTally = detail.querySelector(".tally.critical");
const critPanel = detail.querySelector("#findings-critical");
critTally.click();
check(!critPanel.classList.contains("open"), "clicking a count closes that level");
check(critTally.getAttribute("aria-expanded") === "false",
      "and the handle says it is shut");
critTally.click();
check(critPanel.classList.contains("open"), "clicking it again opens it");

// Every finding is rendered whichever drawer is shut, so a closed level is
// hidden rather than absent - which is what lets find-in-page and any future
// "expand all" reach it, and what keeps the counts honest.
check(detail.querySelectorAll(".finding").length === 1,
      "the findings exist in the page regardless of which drawer is open");

/* One level at a time. Two open drawers put a critical and a note on screen
   at the same weight and leave the reader to find where one list ended, which
   is the wall the drawers were added to remove. The counts stay visible
   whichever is open, so nothing is lost by showing one. */

console.log("\nOne severity open at a time");
console.log("---------------------------");

const twoLevels = [
  { level: "critical", message: "Port 22 is open to the entire internet.",
    rule_id: "sg-1:22", resource_id: "sg-1", rule: {}, fix: null,
    acknowledged: null },
  { level: "warning", message: "Versioning is off.",
    rule_id: "sg-1:versioning", resource_id: "sg-1", rule: {}, fix: null,
    acknowledged: null },
];

const { document: accDoc } = await boot({
  "/resources/security-group/sg-1": () => ({
    resource_type: "security-group", resource_id: "sg-1", settings: {},
    warnings: twoLevels,
    counts: { critical: 1, warning: 1, info: 0, acknowledged: 0 },
  }),
  "/resources/security-group": () => ({
    resource_type: "security-group",
    resources: [{ id: "sg-1", name: "demo" }],
  }),
});

await accDoc.querySelector("#list tr.clickable").click();
await new Promise((r) => setTimeout(r, 60));

const accBody = $(accDoc, "detail-body");
const openLevels = () => [...accBody.querySelectorAll(".group.open")]
  .map((g) => g.id);

check(openLevels().join() === "findings-critical",
      "critical is the one open on arrival");

accBody.querySelector(".tally.warning").click();
check(openLevels().join() === "findings-warning",
      "opening warning closes critical rather than adding to it");
check(accBody.querySelector(".tally.critical").getAttribute("aria-expanded") === "false",
      "and the critical handle says so, not just its panel");

accBody.querySelector(".tally.warning").click();
check(openLevels().length === 0,
      "clicking the open one closes it, so a compact overview is reachable");

check(!detail.querySelector("details.ack-help"),
      "and offers no form to accept it again, being already accepted");

// ------------------------------------------- accepting one from the page

/* The path the CLI used to own. `main.py` had option 15 and the page had a
 * Copy button producing JSON for somebody to paste into a file by hand; the
 * demo feedback was that the CLI should be minimal, so the write moved to
 * POST /acknowledgements and the page submits it.
 *
 * What is checked here is the request body, for the reason the Azure firewall
 * widget below exists at all: that form sent `source` where the route reads
 * `source_address_prefix`, the route accepted the request, and Azure built a
 * group with no rules in it and reported success. A field name is exactly the
 * kind of thing both sides can be internally consistent about and still
 * disagree on. */

console.log("\nAccepting a finding from the page");
console.log("---------------------------------");

const openWarning = {
  // No colon, which is what a security group's per-rule finding really looks
  // like: the id comes straight from AWS as a SecurityGroupRuleId.
  level: "critical", message: "Anyone on the internet can reach port 22.",
  rule_id: "sgr-0a1b2c3d", resource_id: "sg-1", rule: {}, fix: null,
  acknowledged: null,
};

const { document: newAckDoc, sent: ackSent } = await boot({
  "/resources/security-group/sg-1": () => ({
    resource_type: "security-group", resource_id: "sg-1", settings: {},
    warnings: [openWarning],
    counts: { critical: 1, warning: 0, info: 0, acknowledged: 0 },
  }),
  "/resources/security-group": () => ({
    resource_type: "security-group",
    resources: [{ id: "sg-1", name: "demo" }],
  }),
  "/acknowledgements": () => ({ ok: true, message: "Recorded." }),
});

await newAckDoc.querySelector("#list tr.clickable").click();
await new Promise((r) => setTimeout(r, 60));

const ackForm = $(newAckDoc, "detail-body").querySelector("details.ack-help");
check(Boolean(ackForm), "an unacknowledged finding offers a form to accept it");
check(!ackForm.open, "folded shut, so accepting is deliberate rather than reflex");

const ackInputs = ackForm.querySelectorAll("input, textarea");
const reasonBox = [...ackInputs].find((el) => el.tagName === "TEXTAREA");
const nameBox = [...ackInputs].find((el) => el.placeholder === "your name");
const untilBox = [...ackInputs].find((el) => el.type === "date");

check(Boolean(reasonBox && nameBox && untilBox),
      "asking for a reason, an author and an expiry");
check(Boolean(untilBox.value),
      "with the expiry pre-filled, an unseen one being one nobody expects");

reasonBox.value = "this is a deliberate jump box, reviewed in August";
nameBox.value = "richard";

const ackBefore = ackSent.length;
[...ackForm.querySelectorAll("button")]
  .find((b) => b.textContent === "Accept this finding").click();
await new Promise((r) => setTimeout(r, 80));

const ackPost = ackSent.slice(ackBefore)
  .find((r) => r.path === "/acknowledgements" && r.options.method === "POST");

check(Boolean(ackPost), "pressing Accept posts to /acknowledgements");

if (ackPost) {
  const body = JSON.parse(ackPost.options.body);
  check(body.rule_id === "sgr-0a1b2c3d",
        "carrying the rule id the finding actually reported");
  check(body.confirm === body.rule_id,
        "with confirm repeating it, which the route demands");
  check(body.resource_type === "security-group" && body.resource_id === "sg-1",
        "and the resource, so the server can re-scan and check the finding is real");
  check(body.by === "richard", "the author is sent as typed");
  check(body.reason.includes("deliberate jump box"), "and the reason");
  check(/^\d{4}-\d{2}-\d{2}$/.test(body.until),
        "the expiry is a plain date, which is what check_entry parses");
}

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

/* The form was on Create; the list is on Audit. Reading an existing resource
   is auditing it whichever cloud it is in, so the second half of this walk
   changes tab. The cloud does not change with it - which is the thing worth
   asserting, because a toggle that reset on every tab change would be a
   confident answer to "which account am I in" that goes stale on a click. */
$(document, "tabs").querySelector('.tab[data-tab="audit"]').click();
await new Promise((r) => setTimeout(r, 80));

check(document.body.classList.contains("cloud-azure"),
      "moving to Audit keeps the cloud the toggle was left on");

const azRow = document.querySelector("#list tr.clickable");
if (check(Boolean(azRow), "the account is listed")) {
  /* An Azure row's id is its name, so the duplicate Name column was dropped
   * and the table went one identifier wide. What replaces it is where the
   * thing is: two resources can share a name in different resource groups,
   * and until this landed the page could not tell you which one you had. */
  const azHeads = [...document.querySelectorAll("#list th")]
    .map((h) => h.textContent);
  check(azHeads.includes("Resource group") && azHeads.includes("Location"),
        "with columns saying where it is, not the name printed twice");
  check(azHeads.filter((h) => h === "Name").length === 0,
        "and no Name column, because the id already is the name");

  const azCells = [...azRow.querySelectorAll("td")].map((d) => d.textContent);
  check(azCells.includes("scp-demo") && azCells.includes("eastus"),
        "carrying the values the list adapter sent");

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
}, "create");

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

// ------------------------------------------------ the Azure firewall widget

/* An Azure rule is not an AWS rule, and this is where that stops being a
 * comment and becomes an assertion.
 *
 * The page could not submit firewall rules at all until now: the AWS widget
 * produces protocol, from_port, to_port and source, and every rule in a
 * security group is an allow. An Azure rule carries a name, a direction and
 * an access that can be Deny. Sending the AWS shape would have submitted
 * every rule as Allow - a firewall that is not the one on screen, which is
 * the failure this whole project exists to prevent.
 *
 * Priority is deliberately absent and deliberately tested for: the order of
 * the rows is the precedence, and az/nsg assigns the numbers from it. */

console.log("\nThe Azure firewall rules widget");
console.log("-------------------------------");

const AZ_NSG_OPTIONS = {
  rule_direction: [{ value: "Inbound", label: "Inbound — traffic coming in" },
                   { value: "Outbound", label: "Outbound — traffic going out" }],
  rule_access: [{ value: "Allow", label: "Allow — let it through" },
                { value: "Deny", label: "Deny — block it" }],
  rule_protocol: [{ value: "Tcp", label: "TCP" }, { value: "*", label: "All protocols" }],
  rule_port: [{ value: "22", label: "22 — SSH" }, { value: "443", label: "443 — HTTPS" }],
  rule_source: [{ value: "*", label: "* — the entire internet" },
                { value: "VirtualNetwork", label: "VirtualNetwork — only this network" }],
};

const { window: w6, document: doc6, sent: sent6 } = await boot({
  "/resources": () => ({
    resources: [{ key: "azure-nsg", label: "Azure network security group",
                  short_label: "Network security group", provider: "azure",
                  id_label: "Group name", read_only: false,
                  only_ours_label: "only ones this tool made" }],
  }),
  "/resources/azure-nsg/options": () => ({ options: AZ_NSG_OPTIONS }),
  "/resources/azure-nsg": (options) =>
    options.method === "POST"
      ? { resource_type: "azure-nsg", resource_id: "demo-nsg", problems: [],
          settings: {}, warnings: [], counts: { critical: 0, warning: 0, info: 0 } }
      : { resource_type: "azure-nsg", resources: [] },
}, "create");

const nsgBody = $(doc6, "create-body");
const nsgRow = nsgBody.querySelector(".rule");

if (check(Boolean(nsgRow), "the firewall form offers a rule row at all")) {
  const captions = [...nsgRow.querySelectorAll("small")].map((s) => s.textContent);
  check(captions.includes("allow or deny"),
        "with an allow-or-deny control, which no AWS rule has");
  check(captions.includes("direction"), "and a direction");
  check(captions.includes("name"), "and a name, which Azure requires per rule");
  check(!captions.some((c) => /priorit/i.test(c)),
        "and no priority field, the row order being the precedence");

  const denyOption = [...nsgRow.querySelectorAll("option")]
    .find((o) => o.value === "Deny");
  check(Boolean(denyOption), "Deny is offered, not just Allow");
}

// Two rules, the second one a Deny, to prove order and access both survive.
const addRule = [...nsgBody.querySelectorAll("button")]
  .find((b) => b.textContent === "add rule");
addRule.click();
await new Promise((r) => setTimeout(r, 50));

const rows = [...nsgBody.querySelectorAll(".rule")];
check(rows.length === 2, "a second rule row can be added");

/* Fills one rule row, locating each control by the caption above it.
 *
 * Not by searching every select for one holding the value: the protocol menu
 * and the source menu both offer "*", so that finds the protocol control and
 * sets it to "all protocols" while leaving the source empty - which
 * collectSpec then drops as an untouched row. The first version of this
 * helper did exactly that and the failure looked like the widget losing
 * rules. */
function fillRule(row, { name, access, port, source }) {
  const control = (caption) => [...row.querySelectorAll(".labelled")]
    .find((l) => l.querySelector("small")?.textContent === caption);

  control("name").querySelector("input").value = name;
  for (const [caption, value] of [["allow or deny", access],
                                  ["port", port],
                                  ["source", source]]) {
    setSelect(control(caption).querySelector("select"), value);
  }
}

fillRule(rows[0], { name: "allow-web", access: "Allow", port: "443", source: "*" });
fillRule(rows[1], { name: "deny-ssh", access: "Deny", port: "22", source: "*" });

const nameField = [...nsgBody.querySelectorAll(".field")]
  .find((f) => f.querySelector("label")?.textContent === "name");
nameField.querySelector("input").value = "demo-nsg";
const groupField = [...nsgBody.querySelectorAll(".field")]
  .find((f) => f.querySelector("label")?.textContent === "resource group");
groupField.querySelector("input").value = "scp-demo";

const beforeNsg = sent6.length;
[...nsgBody.querySelectorAll("button")]
  .find((b) => b.textContent === "Create").click();
await new Promise((r) => setTimeout(r, 80));

const nsgPost = sent6.slice(beforeNsg).find((r) => r.options.method === "POST");
if (check(Boolean(nsgPost), "pressing Create sends the firewall")) {
  const body = JSON.parse(nsgPost.options.body);

  /* azure_rules, and every field name below, are api/models.py's spelling
     rather than one invented here.

     The first version of this test asserted `rules` and `source`, which the
     stub accepted happily and the real route dropped on the floor: the group
     was built with no rules at all and the page reported success. Only Azure
     could disagree with a stub written to match the page, and it did. These
     names are now the API's, and test_api.py posts the same body to prove the
     two halves still agree. */
  check(Array.isArray(body.azure_rules) && body.azure_rules.length === 2,
        "both rules are carried under azure_rules, the field the route reads");
  check(!("rules" in body),
        "and not under the AWS field, which carries a different shape");

  const [first, second] = body.azure_rules || [{}, {}];
  check(first.name === "allow-web" && second.name === "deny-ssh",
        "in the order the rows sit on screen, which is the precedence");
  check(second.access === "Deny",
        "and a Deny row is submitted as Deny, not silently as Allow");
  check(first.direction === "Inbound",
        "direction is carried, defaulting to inbound");
  check(second.destination_port_range === "22",
        "the port is one Azure-shaped string, not an AWS from/to pair");
  check(second.source_address_prefix === "*",
        "and the source uses Azure's field name, which is what dropped them");
  check(!("from_port" in second) && !("to_port" in second),
        "and carries none of the AWS rule's fields");
  check(!body.azure_rules.some((r) => "priority" in r),
        "no rule names a priority, leaving az/nsg to number them in order");
}

/* The reorder controls, which somebody looked at and asked what they were.
 *
 * Two bare arrows in a form full of firewall settings say nothing about what
 * they move or why it matters, and a title attribute needs a hover to appear
 * and never appears at all on a touch screen. They are captioned now, grouped
 * into one grid cell so the up arrow stops rendering as a wide empty box, and
 * hidden entirely while there is only one rule - because precedence among one
 * rule is not a thing that exists. */

console.log("\nThe precedence controls on a firewall rule");
console.log("------------------------------------------");

const { document: ordDoc } = await boot({
  "/resources": () => ({
    resources: [{ key: "azure-nsg", label: "Azure network security group",
                  short_label: "Network security group", provider: "azure",
                  id_label: "Group name", read_only: false,
                  only_ours_label: "only ones this tool made" }],
  }),
  "/resources/azure-nsg": () => ({ resource_type: "azure-nsg", resources: [] }),
  "/resources/azure-nsg/options": () => ({ options: AZ_NSG_OPTIONS }),
}, "create");

const ordBody = $(ordDoc, "create-body");

check(Boolean([...ordBody.querySelectorAll("p.note")]
        .find((p) => /first rule that matches/.test(p.textContent))),
      "the field explains that order decides, which was written and never shown");

const ordFirstRow = ordBody.querySelector(".rule");
check(Boolean(ordFirstRow.querySelector(".rule-actions")),
      "the buttons are one grid cell, not three loose items in a four-column grid");
check(Boolean([...ordFirstRow.querySelectorAll(".rule-actions small")]
        .find((s) => s.textContent === "order")),
      "and the arrows are captioned, rather than left to be guessed at");

const ordSoleOrder = ordFirstRow.querySelector(".rule-actions .labelled");
check(ordSoleOrder.classList.contains("hidden"),
      "with one rule there is no order to arrange, so it is not offered");

[...ordBody.querySelectorAll("button")]
  .find((b) => b.textContent === "add rule").click();
await new Promise((r) => setTimeout(r, 40));

const ordRows = [...ordBody.querySelectorAll(".rule")];
check(ordRows.length === 2, "adding a second rule");
check(!ordRows[0].querySelector(".rule-actions .labelled").classList.contains("hidden"),
      "makes the order control appear, because now there is an order");

const ordUpFirst = ordRows[0].querySelectorAll(".rule-actions button.move")[0];
const ordDownFirst = ordRows[0].querySelectorAll(".rule-actions button.move")[1];
const ordUpLast = ordRows[1].querySelectorAll(".rule-actions button.move")[0];
const ordDownLast = ordRows[1].querySelectorAll(".rule-actions button.move")[1];

check(ordUpFirst.disabled, "the first rule cannot move earlier");
check(!ordDownFirst.disabled, "but can move later");
check(!ordUpLast.disabled, "the last rule can move earlier");
check(ordDownLast.disabled, "and cannot move later, rather than ignoring the click");

// Name them so the swap is observable.
ordRows[0].querySelectorAll("input")[0].value = "first";
ordRows[1].querySelectorAll("input")[0].value = "second";

ordDownFirst.click();
await new Promise((r) => setTimeout(r, 40));

const ordAfter = [...ordBody.querySelectorAll(".rule")]
  .map((r) => r.querySelectorAll("input")[0].value);
check(ordAfter[0] === "second" && ordAfter[1] === "first",
      "moving a rule later really swaps it, which is what changes precedence");

const ordMovedUp = [...ordBody.querySelectorAll(".rule")][0]
  .querySelectorAll(".rule-actions button.move")[0];
check(ordMovedUp.disabled,
      "and the disabled state follows the rows rather than staying where it was");


// -------------------------------------------- deleting, with progress shown

/* A cascade delete spends four or five minutes in one request, nearly all of
 * it waiting for AWS to detach network interfaces, and the page used to show
 * nothing for the whole of it. It reads the response a line at a time now.
 *
 * What is checked here is mostly the fallback. jsdom's fetch is a stub that
 * answers a plain object with no readable body, which is also what an old
 * proxy or a non-streaming intermediary would produce - so a page that only
 * worked against a real stream would break in both places and be untestable
 * in one of them. */

console.log("\nDeleting, and being told what is happening");
console.log("------------------------------------------");

const { document: delDoc, sent: delSent } = await boot({
  "/resources": () => ({
    resources: [{ key: "network", label: "Network", id_label: "VPC ID",
                  read_only: false, provider: "aws" }],
  }),
  "/resources/network": () => ({
    resource_type: "network",
    resources: [{ id: "vpc-1", name: "demo" }],
  }),
  "/resources/network/options": () => ({ options: {} }),
  "/resources/network/vpc-1": () => ({
    resource_type: "network", resource_id: "vpc-1", settings: {},
    warnings: [], counts: { critical: 0, warning: 0, info: 0 },
  }),
  // The unforced delete refuses, which is what opens the cascade dialog.
  "/resources/network/vpc-1/deletion-plan": () => ({
    resource_type: "network", resource_id: "vpc-1", confirm_with: "vpc-1",
    items: [{ kind: "server", id: "i-1", label: "a machine",
              created_by_this_tool: true }],
    foreign_count: 0, message: "Deleting this would destroy 2 things.",
  }),
});

await new Promise((r) => setTimeout(r, 60));

// Refuse the plain delete so the dialog opens, then accept the forced one.
let refusedOnce = false;
const priorFetch = delDoc.defaultView.fetch;
delDoc.defaultView.fetch = async (url, options = {}) => {
  const path = String(url).split("?")[0].replace("..", "");
  if (path === "/resources/network/vpc-1" && options.method === "DELETE") {
    if (!String(url).includes("force=true")) {
      refusedOnce = true;
      delSent.push({ path, options, url: String(url) });
      return { ok: false, status: 400,
               json: async () => ({ detail: "It still contains machines." }) };
    }
    delSent.push({ path, options, url: String(url) });
    // No body, no getReader: the fallback path.
    return { ok: true, status: 200,
             json: async () => ({ ok: true, message: "Deleted vpc-1." }) };
  }
  return priorFetch(url, options);
};

// The Delete button lives on the row, not in the detail panel.
const delButton = delDoc.querySelector("#list button.danger");
check(Boolean(delButton), "a row offers a delete");

delButton.click();
await new Promise((r) => setTimeout(r, 80));

check(refusedOnce, "the unforced delete is tried first and refused");
check(!$(delDoc, "modal").classList.contains("hidden"),
      "which opens the cascade dialog rather than destroying anything");

const confirmBox = $(delDoc, "modal-body").querySelector("input");
check(Boolean(confirmBox), "the dialog asks for the id to be typed back");

const goButton = $(delDoc, "modal-go");
check(goButton.disabled, "with Delete disabled until it matches");

confirmBox.value = "vpc-1";
confirmBox.dispatchEvent(new delDoc.defaultView.Event("input", { bubbles: true }));
check(!goButton.disabled, "and enabled once it does");

const beforeDelete = delSent.length;
goButton.click();
await new Promise((r) => setTimeout(r, 120));

const forced = delSent.slice(beforeDelete)
  .find((r) => r.options.method === "DELETE" && r.url.includes("force=true"));

check(Boolean(forced), "pressing Delete sends the forced delete");
check(forced.url.includes("stream=true"),
      "asking for it a step at a time, which is the whole point");
check(forced.url.includes("confirm=vpc-1"),
      "still repeating the id, which the server demands regardless");
check($(delDoc, "modal").classList.contains("hidden"),
      "and the dialog closes when it finishes, even with nothing to stream");



// ------------------------------------------------------------- the dashboard

/* Counting what is in an account and judging it are different questions with
 * very different costs. One list call per type answers in a second; scanning
 * is seven AWS calls per bucket one after another, which this repository
 * already records as visibly slow past a demo account. So the landing page
 * counts, and posture is a button.
 *
 * What must never happen is the two being confused. A type nobody has scanned
 * says "not scanned" rather than showing a zero - the same failure the list
 * had on its first load, where worst_level being null for both "nothing
 * found" and "nothing looked for" made every row read as clean. */

console.log("\nThe dashboard");
console.log("-------------");

const { document: dashDoc, sent: dashSent } = await boot({
  // One type with something in it, so "counted but not judged" is reachable.
  // With every type empty each card would read "none" and the distinction
  // this whole panel turns on could not be observed.
  // Counts on the scanning pass and not on the counting one, which is the
  // difference the real route turns on. Answering both without counts modelled
  // a scan that came back empty-handed for every row, and the dashboard now
  // reports exactly that - correctly - which is not what this fixture is here
  // to exercise.
  "/resources/security-group": (options, url) => ({
    resource_type: "security-group",
    resources: [{ id: "sg-1", name: "demo" }, { id: "sg-2", name: "other" }]
      .map((r) => url.includes("with_scan=true")
        ? { ...r, counts: { critical: 0, warning: 0, info: 0, accepted: 0 },
            worst_level: null }
        : r),
  }),
  "/activity": () => ({ activity: [
    { at: "2026-08-15T14:31:17-0400", method: "DELETE",
      path: "/resources/network/vpc-1", status: 400, outcome: "refused",
      why: "confirm did not match" },
  ] }),
}, "dashboard");

check(!$(dashDoc, "dashboard").classList.contains("hidden"),
      "the page opens on the dashboard");
check($(dashDoc, "sidebar").classList.contains("hidden"),
      "with no resource picker, the question being about the whole account");
check(dashDoc.body.classList.contains("no-picker"),
      "and the layout told so, because hiding the sidebar alone left the "
      + "content in the column that was reserved for it");

const dashCards = [...dashDoc.querySelectorAll(".dash-card")];
check(dashCards.length === awsTypes.length,
      "one card per type in the cloud being shown");
check(dashCards.every((c) => c.querySelector(".dash-state").textContent !== ""),
      "each saying what is known about it");
/* This was a button, on the reasoning that scanning is the slow path - seven
   AWS calls per bucket, one after another. Measured instead of assumed: 3.4
   seconds for a whole AWS account and 3.6 for a whole subscription, because
   the types are asked in parallel and only the resources inside one type are
   serial. Three seconds is not a reason to make somebody press a button, and
   a card reading "not scanned" is a card that has not answered the question
   the page exists to answer. */
check(dashSent.some((r) => r.url.includes("with_scan=true")),
      "the dashboard scans itself rather than waiting to be asked");
check(dashSent.filter((r) => r.url.includes("with_scan=true")).length
        === awsTypes.length,
      "one scan per type, asked together rather than one after another");
check(dashCards.some((c) =>
        /critical|warning|clean|none/.test(c.querySelector(".dash-state").textContent)),
      "so the cards say what was found instead of that nothing was looked at");
check($(dashDoc, "dash-body").querySelector(".scan-when").textContent
        .includes("since last scan"),
      "and the panel says the numbers are as of that scan");
check($(dashDoc, "scan-all").textContent === "Scan again",
      "the button becomes a re-scan, the first one having already happened");

/* A resource the login could not read is not a resource with nothing wrong in
   it, and the dashboard scored it as one.

   GET /resources/{type}?with_scan=true returns such a row rather than dropping
   it - counts null, `unreachable` naming the permission - because a resource
   you cannot audit is exactly the one worth knowing about. The aggregation
   here skipped every row with no counts and never read `unreachable` at all,
   so one readable clean alarm beside one unreadable one rendered as "clean",
   under the headline "Nothing critical or warning".

   The Audit list has always got this right and renders "?" for such a row. The
   summary above it was the half that lied, which is the worse half to lie in,
   and it is the same failure this panel already records learning once: nothing
   here may print a verdict it did not earn by scanning. */
const { document: partialDoc } = await boot({
  "/resources/alarm": (options, url) => ({
    resource_type: "alarm",
    resources: url.includes("with_scan=true")
      ? [{ id: "billing", name: "billing", worst_level: null,
           counts: { critical: 0, warning: 0, info: 0, accepted: 0 } },
         { id: "locked", name: "locked", worst_level: null, counts: null,
           unreachable: "cloudwatch:DescribeAlarms" }]
      : [{ id: "billing", name: "billing" }, { id: "locked", name: "locked" }],
  }),
}, "dashboard");

/* What has already been decided about, attached to the severity it belongs to.

   The first version of this trailed one number on the end - "2 critical, 2
   warning, 3 accepted" - which reads as seven findings and never says which
   three are spoken for, so a reader cannot tell whether anything is
   outstanding without opening the type.

   Still not subtracted, and that is the part worth holding. "1 warning" on a
   bucket carrying two accepted criticals is the reading this whole panel
   exists to prevent: a summary that empties the screen is how people stop
   reading the screen. The severities stay whole and the parenthesis says how
   much of each has been decided about. */
const { document: ackDashDoc } = await boot({
  "/resources/security-group": (options, url) => ({
    resource_type: "security-group",
    resources: url.includes("with_scan=true")
      ? [{ id: "sg-1", name: "demo", worst_level: "critical",
           counts: { critical: 2, warning: 2, info: 0, acknowledged: 3,
                     accepted: { critical: 2, warning: 1, info: 0 } } }]
      : [{ id: "sg-1", name: "demo" }],
  }),
}, "dashboard");

const ackCard = [...ackDashDoc.querySelectorAll(".dash-card")].find(
  (c) => c.querySelector(".dash-name").textContent === "Security group");
const ackState = ackCard.querySelector(".dash-state").textContent;

check(ackState === "1 warning (2 C, 1 W accepted)",
      "the card leads with what is left to do, not with what was already answered");
check(!ackCard.classList.contains("has-critical"),
      "and is not styled as a crisis when every critical has been accepted");
check(ackCard.classList.contains("has-warning"),
      "but is styled by the warning that has not");
check(!ackCard.classList.contains("clean"),
      "and never reads clean, because findings exist and were decided about");

const ackNote = $(ackDashDoc, "dash-body").querySelector(".verdict-note");
check($(ackDashDoc, "dash-body").querySelector(".verdict-line").textContent
        === "No critical findings, 1 warning",
      "the headline agrees with the cards rather than counting them differently");
check(Boolean(ackNote) && /2 criticals and 1 warning already accepted/.test(ackNote.textContent),
      "and says what was accepted");
check(Boolean(ackNote) && /not counted above/.test(ackNote.textContent),
      "and that it is not inside the number above, which is otherwise unreadable");

/* Everything found, and everything already answered. Not the same state as
   nothing being found, and it must not borrow that wording: what is here is a
   set of decisions somebody made, and those are worth going back to. */
const { document: allAckDoc } = await boot({
  "/resources/security-group": (options, url) => ({
    resource_type: "security-group",
    resources: url.includes("with_scan=true")
      ? [{ id: "sg-1", name: "demo", worst_level: "critical",
           counts: { critical: 1, warning: 1, info: 0, acknowledged: 2,
                     accepted: { critical: 1, warning: 1, info: 0 } } }]
      : [{ id: "sg-1", name: "demo" }],
  }),
}, "dashboard");

const allAckCard = [...allAckDoc.querySelectorAll(".dash-card")].find(
  (c) => c.querySelector(".dash-name").textContent === "Security group");

check(allAckCard.querySelector(".dash-state").textContent
        === "all accepted (1 C, 1 W)",
      "a type with nothing outstanding says so, and says what it holds");
check(!allAckCard.classList.contains("clean"),
      "and is not called clean, which would claim nothing was ever found");
check(!allAckCard.classList.contains("has-critical")
        && !allAckCard.classList.contains("has-warning"),
      "nor coloured as though something needs doing");
check($(allAckDoc, "dash-body").querySelector(".verdict-line").textContent
        === "Nothing outstanding",
      "and the headline reaches its own wording for it");

const alarmCard = [...partialDoc.querySelectorAll(".dash-card")].find(
  (c) => c.querySelector(".dash-name").textContent === "Alarm");
const alarmState = alarmCard.querySelector(".dash-state").textContent;

check(alarmState !== "clean",
      "a type holding one unreadable resource never reads as clean");
check(/could not be read/.test(alarmState),
      "the card says how many were not looked at instead of leaving them out");
check(!alarmCard.classList.contains("clean"),
      "and is not styled clean either, which is read before the words are");
check(partialDoc.querySelector(".verdict-line").textContent === "Scan incomplete",
      "the headline calls the account's scan short rather than calling it clean");
check(partialDoc.querySelector(".verdict-note").textContent.includes("Alarm"),
      "and names the type, so the gap is somewhere rather than everywhere");

// The dashboard is a way in, not a dead end.
const groupCard = dashCards.find((c) =>
  c.querySelector(".dash-name").textContent === "Security group");
groupCard.click();
await new Promise((r) => setTimeout(r, 80));
check(!$(dashDoc, "listing").classList.contains("hidden"),
      "clicking a card opens that type where it can be acted on");
check($(dashDoc, "dashboard").classList.contains("hidden"),
      "landing on Audit rather than leaving both on screen");

// Recent activity: the half of this tool's behaviour that leaves no other trace.
const activityRows = [...dashDoc.querySelectorAll(".activity li")];
if (check(activityRows.length === 1, "recent activity is listed")) {
  const row = activityRows[0];
  check(row.textContent.includes("DELETE /resources/network/vpc-1"),
        "naming what was asked for");
  check(row.querySelector(".outcome").textContent === "refused",
        "and how it ended - a refusal leaves no trace in CloudTrail, because "
        + "nothing happened");
  check(row.textContent.includes("confirm did not match"),
        "and why, where the log says");
}


// ------------------------------------------------- the account, in one line

/* The grid answers "how many of each", which took nine cards to add up into
 * the thing somebody came to find out. The headline says it once.
 *
 * Its wording is the part that can go wrong quietly, so these drive the
 * cases rather than the happy one. The rule underneath all of them is the one
 * this repository states about the IAM scanner and then shipped wrong on the
 * front page once already: a partial scan that reads as a pass is the single
 * way this tool can actively mislead. */

console.log("\nThe account in one line");
console.log("-----------------------");

const verdictStub = (perType) => ({
  "/resources": () => ({ resources: [
    { key: "security-group", label: "Security group", short_label: "Security group",
      provider: "aws", id_label: "Group ID", read_only: false },
    { key: "bucket", label: "Storage bucket", short_label: "Storage bucket",
      provider: "aws", id_label: "Bucket name", read_only: false },
  ] }),
  "/activity": () => ({ activity: [] }),
  ...perType,
});

const oneRow = (counts) => ({ resources: [{ id: "a", name: "a", counts }] });
const readVerdict = (doc) => doc.querySelector(".verdict").textContent
  .replace(/\s+/g, " ").trim();

// Criticals lead, and the warnings are still said.
const { document: vA } = await boot(verdictStub({
  "/resources/security-group": () => oneRow({ critical: 2, warning: 3, info: 0 }),
  "/resources/bucket": () => oneRow({ critical: 1, warning: 4, info: 0 }),
}), "dashboard");
await new Promise((r) => setTimeout(r, 120));
check(readVerdict(vA).startsWith("3 critical findings"),
      "criticals across every type are totalled and lead the sentence");
check(readVerdict(vA).includes("7 warnings"),
      "and the warnings are still reported, not hidden behind them");
check(vA.querySelector(".verdict").classList.contains("is-critical"),
      "with the severity on the rule, so one glance is enough");

// No criticals is good news and unfinished news.
const { document: vB } = await boot(verdictStub({
  "/resources/security-group": () => oneRow({ critical: 0, warning: 2, info: 0 }),
  "/resources/bucket": () => oneRow({ critical: 0, warning: 0, info: 1 }),
}), "dashboard");
await new Promise((r) => setTimeout(r, 120));
check(readVerdict(vB) === "No critical findings, 2 warnings",
      "no criticals says so, and says what is left rather than \"clean\"");

// A type that could not be read is not a type with nothing wrong in it.
const { document: vC } = await boot(verdictStub({
  "/resources/security-group": () => oneRow({ critical: 0, warning: 0, info: 0 }),
  "/resources/bucket": () => ({ __status: 503, detail: "Azure is not configured" }),
}), "dashboard");
await new Promise((r) => setTimeout(r, 150));
check(!/clean|nothing critical/i.test(readVerdict(vC)),
      "an unreadable type is never rounded down to a clean account");
check(readVerdict(vC).includes("Scan incomplete"),
      "it says the scan did not finish");
check(readVerdict(vC).includes("Storage bucket"),
      "and names which type it could not read");

// An empty account is empty, not safe.
const { document: vD } = await boot(verdictStub({
  "/resources/security-group": () => ({ resources: [] }),
  "/resources/bucket": () => ({ resources: [] }),
}), "dashboard");
await new Promise((r) => setTimeout(r, 120));
check(readVerdict(vD).includes("Nothing in this account yet"),
      "an account with no resources says that, rather than passing them");
check(!vD.querySelector(".verdict").classList.contains("is-clean"),
      "and is not dressed as a clean bill of health for things that do not exist");

// The genuinely clean case still exists and is allowed to say so.
const { document: vE } = await boot(verdictStub({
  "/resources/security-group": () => oneRow({ critical: 0, warning: 0, info: 0 }),
  "/resources/bucket": () => oneRow({ critical: 0, warning: 0, info: 2 }),
}), "dashboard");
await new Promise((r) => setTimeout(r, 120));
check(vE.querySelector(".verdict").classList.contains("is-clean"),
      "everything read and nothing found is the one case that reads as clean");
check(readVerdict(vE).includes("2 resources"),
      "and says how much was looked at, so the claim carries its own scope");


// ------------------------------------------------------------ empty states

/* Two of these are dangerous rather than merely thin. "Nothing here." under a
 * heading naming one resource type, in a tool whose job is finding what is
 * wrong, reads as a clean bill on the account - and means only that this one
 * kind of resource does not exist. The distinction is the whole point of the
 * second line, so it is what these check. */

console.log("\nEmpty states");
console.log("------------");

const { document: emptyDoc } = await boot({
  "/resources/security-group": () => ({
    resource_type: "security-group", resources: [],
  }),
}, "audit");

const emptyPanel = $(emptyDoc, "list").querySelector(".nothing");
if (check(Boolean(emptyPanel), "an empty list gets a panel rather than a sentence")) {
  const said = emptyPanel.textContent.replace(/\s+/g, " ");
  check(said.includes("No security group in this account"),
        "naming what is empty, which is one kind of resource");
  check(/not a verdict on the account/i.test(said),
        "and saying what it does not mean, because a bare \"nothing here\" in "
        + "this tool reads as a clean account");
  check(!emptyPanel.classList.contains("is-clean"),
        "so it is not dressed as a pass");
}

const waiting = $(emptyDoc, "detail-body").querySelector(".nothing");
check(Boolean(waiting) && /Nothing selected/.test(waiting.textContent),
      "the detail panel says it is waiting rather than issuing an instruction");

/* The one empty state that is a verdict, and has earned it: this resource was
 * read just now and every rule ran over it. */
const { document: cleanDoc } = await boot({
  "/resources/security-group": () => ({
    resource_type: "security-group", resources: [{ id: "sg-1", name: "demo" }],
  }),
  "/resources/security-group/sg-1": () => ({
    resource_type: "security-group", resource_id: "sg-1", settings: {},
    warnings: [], counts: { critical: 0, warning: 0, info: 0 },
  }),
}, "audit");
await cleanDoc.querySelector("#list tr.clickable").click();
await new Promise((r) => setTimeout(r, 80));

const verdictPanel = $(cleanDoc, "detail-body").querySelector(".nothing");
if (check(Boolean(verdictPanel), "a resource with no findings says so")) {
  check(verdictPanel.classList.contains("is-clean"),
        "and this one *is* a verdict, because the scan really ran over it");
  check(/every rule/i.test(verdictPanel.textContent),
        "saying that every rule ran, which is what separates it from the "
        + "empty list above");
}

// ------------------------------------------- a multi-select sends every choice

/* The widest-reaching bug this suite never saw, because it never drove a
 * multi-select at all.
 *
 * multiChoice built a real <select multiple> and then did
 * `select.value = () => [...select.selectedOptions].map(o => o.value)`.
 * `value` is an accessor on HTMLSelectElement.prototype, so that assignment
 * went through the setter and no own property was ever created: `typeof
 * el.value` stayed "string", collectSpec took its plain-<input> branch and
 * split that string on commas, and a multi-select's value getter answers with
 * the FIRST selected option and never contains a comma. Every choice after the
 * first was discarded in silence, on the way to the create and to the live
 * pre-flight alike - so the tool judged a machine nobody had asked for and
 * agreed with itself about it. */

console.log("\nA multi-select submits every option chosen");
console.log("------------------------------------------");

const { document: multiDoc, sent: multiSent } = await boot({
  "/resources": () => ({
    resources: [
      { key: "instance", label: "Server", short_label: "Server",
        provider: "aws", id_label: "Instance ID", read_only: false },
    ],
  }),
  "/resources/instance": (options) =>
    options.method === "POST"
      ? { resource_type: "instance", resource_id: "i-1", problems: [],
          settings: {}, warnings: [],
          counts: { critical: 0, warning: 0, info: 0 } }
      : { resource_type: "instance", resources: [] },
  "/resources/instance/options": () => ({
    options: {
      instance_type: [{ value: "t3.micro", label: "t3.micro" }],
      key_name: [{ value: "demo-key", label: "demo-key" }],
      security_group_ids: [
        { value: "sg-1", label: "sg-1" },
        { value: "sg-2", label: "sg-2" },
        { value: "sg-3", label: "sg-3" },
      ],
      subnet_id: [{ value: "subnet-1", label: "subnet-1" }],
    },
  }),
}, "create");

const multiBody = $(multiDoc, "create-body");
const multiSelect = [...multiBody.querySelectorAll("select")]
  .find((s) => s.multiple);

if (check(Boolean(multiSelect), "the form offers a real multi-select")) {
  multiBody.querySelector("input").value = "demo-server";
  // Two of the three, and deliberately not the adjacent pair: the old code
  // kept whichever option came first in the list, so selecting sg-1 and sg-2
  // would have passed for the wrong reason.
  for (const option of multiSelect.options) {
    if (option.value !== "sg-2") option.selected = true;
  }

  const beforeMulti = multiSent.length;
  [...multiBody.querySelectorAll("button")]
    .find((b) => b.textContent === "Create").click();
  await new Promise((resolve) => setTimeout(resolve, 50));

  const post = multiSent.slice(beforeMulti)
    .find((r) => r.options.method === "POST");
  if (check(Boolean(post), "and submits it")) {
    const spec = JSON.parse(post.options.body);
    check(Array.isArray(spec.security_group_ids)
          && spec.security_group_ids.length === 2,
          "carrying both groups chosen, rather than only the first");
    check(JSON.stringify(spec.security_group_ids) === '["sg-1","sg-3"]',
          "and exactly the ones chosen");
  }
}

// ------------------------------------- the browser sweep still has a page to walk

/* browse.mjs is not in `npm test` - it needs a running server and a real
 * account - so nothing here notices when it stops working. It stopped working
 * at the three-tab redesign and nobody saw for weeks.
 *
 * It read `#types` immediately after load. The page opens on the Dashboard,
 * which has no type picker, so it enumerated zero tabs, walked none of them,
 * and printed "no console errors on any tab of any cloud" - output identical
 * to a clean run unless you notice the list is empty. The instrument this
 * project calls its most important one was reporting a clean sweep of nothing.
 *
 * These pin the structural anchors it steers by. They are cheap, and the thing
 * they protect is expensive: a broken sweep is worse than no sweep, because
 * the tick gets believed. */

console.log("\nThe browser sweep's anchors still exist on the page");
console.log("---------------------------------------------------");

const sweepDoc = (await boot(undefined, "create")).document;

for (const tab of ["dashboard", "create", "audit"]) {
  check(Boolean(sweepDoc.querySelector(`#tabs .tab[data-tab="${tab}"]`)),
        `browse.mjs can reach the ${tab} tab`);
}
check(Boolean(sweepDoc.querySelector("#types")),
      "and the type picker it enumerates is still called #types");
check(sweepDoc.querySelectorAll("#cloud-toggle .opt").length >= 2,
      "and the cloud toggle still offers both clouds by data-cloud");
check([...sweepDoc.querySelectorAll("#cloud-toggle .opt")]
        .every((o) => o.dataset.cloud),
      "each carrying the data-cloud the sweep reads to know which halves exist");

// The picker is populated per page-tab, which is the fact the sweep got wrong.
// Asserting it here means a redesign that empties it fails in npm test rather
// than silently in an instrument nobody reads the output of closely.
check(sweepDoc.querySelectorAll("#types button").length > 0,
      "and on the Create tab it actually lists types, which is what the sweep "
      + "walks");

// ------------------------------------------- the static website hosting switch

/* The one control on the detail panel that changes the account rather than
 * describing it, so where it is and what it sends both matter.
 *
 * It lives in the panel head, not the body. It was under the findings first,
 * which ordered it correctly and placed it wrong: a hardened bucket carries
 * five findings, so the switch rendered below the fold and the panel looked
 * like it had none. That is asserted here rather than left to a comment,
 * because "it is on the page" and "somebody can see it" are different claims
 * and only the first one was ever true. */

console.log("\nThe static website switch is in the panel head, and says where it wants to end up");
console.log("--------------------------------------------------------------------------------");

const bucketStub = (website, extra = {}) => ({
  "/resources": () => ({
    resources: [...STUB_TYPES,
      { key: "bucket", label: "Storage bucket", short_label: "Storage bucket",
        provider: "aws", id_label: "Bucket name", read_only: false,
        only_ours_label: "only ones this tool made" }],
  }),
  "/resources/bucket": () => ({
    resource_type: "bucket", resources: [{ id: "demo-bucket", name: "demo-bucket" }],
  }),
  "/resources/bucket/demo-bucket": () => ({
    resource_type: "bucket", resource_id: "demo-bucket",
    settings: { bucket: "demo-bucket", website, unreadable: {}, ...extra },
    warnings: [], counts: { critical: 0, warning: 0, info: 0 },
  }),
  "/resources/bucket/demo-bucket/website": () => ({
    ok: true, message: "Static website hosting is on, serving index.html.",
  }),
});

async function openBucket(stub) {
  const { document: doc, sent } = await boot(stub, "audit");
  doc.querySelector("#types button[data-key=\"bucket\"]")?.click();
  await new Promise((r) => setTimeout(r, 80));
  const row = doc.querySelector("#list tr.clickable");
  if (row) row.click();
  await new Promise((r) => setTimeout(r, 80));
  return { doc, sent };
}

const { doc: offDoc, sent: offSent } =
  await openBucket(bucketStub({ enabled: false, index: null, error: null }));

const offSwitch = offDoc.querySelector(".website-switch");
if (check(Boolean(offSwitch), "a bucket's detail panel carries the switch")) {
  check(offSwitch.closest("#detail-actions") !== null,
        "in the panel head, where no number of findings can push it off screen");
  check(offDoc.querySelector("#detail-body .website-switch") === null,
        "and not in the body, which is where it was hiding below the fold");
  check(/website: off/i.test(offSwitch.textContent),
        "reading its position out of the settings already on screen");
  const button = offSwitch.querySelector("button");
  check(button.textContent === "Turn on",
        "and the button offers the direction it is not already in");
  check(!offSwitch.querySelector("a"),
        "with no address, an endpoint that answers nothing yet reading as a "
        + "promise already kept");

  const before = offSent.length;
  button.click();
  await new Promise((r) => setTimeout(r, 80));
  const post = offSent.slice(before).find(
    (r) => r.path.includes("/website") && r.options.method === "POST");

  if (check(Boolean(post), "pressing it posts to the bucket's website route")) {
    check(JSON.parse(post.options.body).enabled === true,
          "asking for the state it wants rather than for a toggle");
  }
}

const { doc: onDoc } =
  await openBucket(bucketStub({ enabled: true, index: "index.html", error: null }));

const onSwitch = onDoc.querySelector(".website-switch");
if (check(Boolean(onSwitch), "a bucket already hosting says so")) {
  check(/website: on/i.test(onSwitch.textContent), "in the same two words");
  check(onSwitch.querySelector("button").textContent === "Turn off",
        "and offers the other direction");
  const link = onSwitch.querySelector("a");
  check(Boolean(link) && link.href.startsWith("http://demo-bucket.s3-website-us-east-1"),
        "showing the address, spelled with the dash us-east-1 takes");
  check(Boolean(link) && /http only/i.test(link.title),
        "and carrying why a live endpoint can still refuse everyone, which is "
        + "AWS's limit rather than this tool's shortcut");
}

/* A refused read is not an off. */
const { doc: blindDoc } = await openBucket({
  ...bucketStub({ enabled: false, index: null, error: null }),
  "/resources/bucket/demo-bucket": () => ({
    resource_type: "bucket", resource_id: "demo-bucket",
    settings: { bucket: "demo-bucket", website: null,
                unreadable: { website: "s3:GetBucketWebsite" } },
    warnings: [], counts: { critical: 0, warning: 0, info: 0 },
  }),
});

const blindSwitch = blindDoc.querySelector(".website-switch");
if (check(Boolean(blindSwitch), "an unreadable website setting still gets a line")) {
  check(/s3:GetBucketWebsite/.test(blindSwitch.textContent),
        "naming the permission that is missing");
  check(!blindSwitch.querySelector("button"),
        "and offering no switch, because one that cannot know its own "
        + "position should not offer to move");
}

/* The control acts on one bucket, so it must not outlive the selection. */
const { doc: clearDoc } =
  await openBucket(bucketStub({ enabled: true, index: "index.html", error: null }));
check(Boolean(clearDoc.querySelector("#detail-actions .website-switch")),
      "the switch is there while a bucket is selected");
clearDoc.querySelector("#types button[data-key=\"security-group\"]").click();
await new Promise((r) => setTimeout(r, 100));
check(!clearDoc.querySelector("#detail-actions .website-switch"),
      "and is gone once the selection is, rather than staying pointed at the "
      + "last bucket looked at");

/* And the same control on the create side, where the bucket has just been made.
 *
 * Without it, turning hosting on for the bucket you are looking at meant
 * crossing to Audit, picking the type and finding the row - three navigations
 * to something that was on screen a second earlier. */

console.log("\nThe create panel offers hosting on the bucket it just made");
console.log("---------------------------------------------------------");

const CREATED = {
  resource_type: "bucket", resource_id: "born-bucket", problems: [],
  settings: { bucket: "born-bucket", website: { enabled: false, index: null },
              unreadable: {} },
  warnings: [], counts: { critical: 0, warning: 0, info: 0 },
};

const { document: madeDoc, sent: madeSent } = await boot({
  "/resources": () => ({
    resources: [...STUB_TYPES,
      { key: "bucket", label: "Storage bucket", short_label: "Storage bucket",
        provider: "aws", id_label: "Bucket name", read_only: false,
        only_ours_label: "only ones this tool made" }],
  }),
  "/resources/bucket/options": () => ({ options: {} }),
  "/resources/bucket/check": () => ({
    resource_type: "bucket", warnings: [],
    counts: { critical: 0, warning: 0, info: 0 },
  }),
  "/resources/bucket": (options) =>
    options.method === "POST" ? CREATED
                              : { resource_type: "bucket", resources: [] },
}, "create");

madeDoc.querySelector("#types button[data-key=\"bucket\"]").click();
await new Promise((r) => setTimeout(r, 120));

const form = $(madeDoc, "create-body");
// By property, not attribute. The form's text inputs are built without an
// explicit type, so `input[type=text]` matches none of them - the attribute
// selector reads the attribute, and the default lives on the property.
const inputs = [...form.querySelectorAll("input")];
const boxes = inputs.filter((i) => i.type === "checkbox");
check(boxes.length === 2,
      "the bucket form offers hosting as its own switch, beside secure defaults");
check(/serve a static website/i.test(form.textContent),
      "named for what it does rather than for the API field");
check(/does not make the bucket public/i.test(form.textContent),
      "and saying plainly that ticking it publishes nothing, which is the "
      + "thing a reader would otherwise assume");

// Tick it, and it has to reach the request body.
inputs.find((i) => i.type === "text").value = "born-bucket";
boxes[1].checked = true;

const madeBefore = madeSent.length;
[...form.querySelectorAll("button")].find((b) => b.textContent === "Create").click();
await new Promise((r) => setTimeout(r, 150));

const createPost = madeSent.slice(madeBefore).find(
  (r) => r.path.startsWith("/resources/bucket") && r.options.method === "POST"
         && !r.path.includes("/check"));
if (check(Boolean(createPost), "creating posts the spec")) {
  check(JSON.parse(createPost.options.body).website === true,
        "carrying the hosting choice, not dropping it on the floor");
}

const madeSwitch = madeDoc.querySelector("#create-out .website-switch");
if (check(Boolean(madeSwitch),
          "and the result panel carries the switch for the bucket just made")) {
  check(/website: off/i.test(madeSwitch.textContent),
        "reading its position from the settings the create call returned");
  check(madeDoc.querySelector("#create-out").textContent.includes("born-bucket"),
        "beside the name of the thing it acts on");
}

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
