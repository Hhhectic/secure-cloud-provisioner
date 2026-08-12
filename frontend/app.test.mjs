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
const STUB_TYPES = [
  { key: "security-group", label: "Security group",
    id_label: "Group ID", read_only: false,
    only_ours_label: "only ones this tool made", provider: "aws" },
  // Audited and still filterable, which is the pair that broke the old rule:
  // the page used to disable the box for anything read_only.
  { key: "snapshot", label: "Disk backup",
    id_label: "Snapshot ID", read_only: true,
    only_ours_label: "only ones this tool made", provider: "aws" },
  // Audited with nothing to narrow by.
  { key: "iam", label: "Account access", id_label: "Account ID",
    read_only: true, only_ours_label: null, provider: "aws" },
  { key: "alarm", label: "Alarm", id_label: "Alarm name",
    read_only: false, only_ours_label: "only ones this tool made",
    provider: "aws" },
  // The second cloud, which the page has never been asked about. It reaches
  // these through the registry like anything else, and that is the claim
  // worth testing: nothing in app.js knows the word Azure.
  { key: "azure-storage", label: "Azure storage account",
    id_label: "Account name", read_only: true, only_ours_label: null,
    provider: "azure" },
];

const AWS_TYPES = STUB_TYPES.filter((t) => t.provider === "aws");
const AZURE_TYPES = STUB_TYPES.filter((t) => t.provider === "azure");

/* The two clouds as /resources describes them.

   Deliberately not the real lists. What is being tested is that the page
   renders whatever it is handed - the labels, the word for where things go,
   and which field a location travels in - rather than that it agrees with
   api/registry.py about Azure. A stub repeating the real values could not
   tell a page that reads them from one that has them written down. */
const STUB_PROVIDERS = [
  { key: "aws", label: "AWS", place_label: "Region", place_field: null,
    places: [{ value: "us-east-1", label: "us-east-1 — N. Virginia" },
             { value: "eu-west-2", label: "eu-west-2 — London" }],
    default_place: "us-east-1",
    caution: "This talks to a real AWS account.",
    blueprints: ["bastion"] },
  { key: "azure", label: "Azure", place_label: "Location",
    place_field: "location",
    places: [{ value: "eastus", label: "eastus — Virginia" },
             { value: "uksouth", label: "uksouth — London" }],
    default_place: "eastus",
    caution: "This talks to a real Azure subscription.",
    blueprints: [] },
];


function fakeApi(overrides = {}) {
  const sent = [];

  const routes = {
    "/health": () => ({ status: "ok" }),
    "/resources": () => ({ resources: STUB_TYPES,
                           providers: STUB_PROVIDERS }),
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

/* Fills the named text fields, presses Create, and returns the request body.

   Fields are found by their caption because that is what a person sees; a
   test driving the form by index would keep passing after the captions
   stopped matching what the boxes do. */
async function submitCreate(window, doc, sent, values) {
  const body = $(doc, "create-body");
  const rows = [...body.querySelectorAll(".field")];

  for (const [name, value] of Object.entries(values)) {
    const row = rows.find((r) => r.querySelector("label")?.textContent === name);
    const input = row && row.querySelector("input");
    if (input) input.value = value;
  }

  const before = sent.length;
  const create = [...body.querySelectorAll("button")]
    .find((b) => b.textContent === "Create");
  if (!create) return null;

  create.click();
  await new Promise((r) => setTimeout(r, 60));

  const post = sent.slice(before).find((r) => r.options.method === "POST");
  return post ? JSON.parse(post.options.body) : null;
}

// --------------------------------------------------------------- the page

console.log("\nBooting");
console.log("-------");

const { window, document, sent } = await boot();

check($(document, "health").textContent === "API up",
      "the health pill reflects a reachable API");
// Counted from the stub rather than written as a number, so adding a type to
// the stub cannot silently make this assertion about something else. One
// cloud's worth, because the page shows one cloud at a time.
check($(document, "types").children.length === AWS_TYPES.length,
      "a tab appears for every resource type in the cloud being shown");
check([...$(document, "types").children]
        .some((b) => b.textContent.includes("audit only")),
      "an audited type is labelled as one");

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
        read_only: false, provider: "aws" },
    ],
    providers: STUB_PROVIDERS,
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

/* The switch is built from what /resources declares, so these assertions are
   about a page that counts providers rather than one that knows there are
   two. The stub's labels and place names are deliberately not the real ones
   for the same reason: a page reading them and a page with them written down
   would be indistinguishable if the stub agreed with api/registry.py. */
const cloudSwitch = $(document, "cloud");

check(cloudSwitch.children.length === STUB_PROVIDERS.length,
      "the switch has one position per provider the API declares");
check([...cloudSwitch.children].map((b) => b.textContent).join() ===
        STUB_PROVIDERS.map((p) => p.label).join(),
      "labelled with the names the server gave, in its order");
check(![...$(document, "types").children]
        .some((b) => b.textContent.includes("Azure storage account")),
      "a type belonging to the other cloud is not on this one's page");

const azurePosition = [...cloudSwitch.children]
  .find((b) => b.dataset.provider === "azure");

await azurePosition.click();
await new Promise((r) => setTimeout(r, 60));

check(azurePosition.getAttribute("aria-checked") === "true",
      "moving the switch marks the position it moved to, for a screen reader too");
check($(document, "types").children.length === AZURE_TYPES.length,
      "and the tabs become that cloud's types, not both clouds' at once");

/* An AWS region is a property of the connection and an Azure location is a
   property of the resource. The page shows one control and changes the word,
   which is the only honest way to present two things that are not the same. */
check($(document, "place-label").textContent === "Location",
      "the word for where things go follows the cloud");
check([...$(document, "place").options].map((o) => o.value).join() ===
        STUB_PROVIDERS[1].places.map((p) => p.value).join(),
      "and the places on offer are that cloud's, not the other one's");
check($(document, "place").value === "eastus",
      "starting at the default the server named");

check($(document, "caution").textContent.includes("Azure subscription"),
      "the warning at the top names the account actually being touched");
check(!$(document, "caution").textContent.includes("AWS"),
      "rather than promising AWS on a page that cannot reach it");

/* The bastion is VPCs, subnets and EC2 instances. Which cloud has a blueprint
   is the server's answer here as well - the page has no list of its own. */
check($(document, "blueprint").classList.contains("hidden"),
      "a blueprint the current cloud does not have is not offered");

const azTab = [...$(document, "types").children]
  .find((b) => b.textContent.includes("Azure storage account"));

check(Boolean(azTab), "a tab appears for a type from the second cloud");
check(azTab.textContent.includes("audit only"),
      "labelled audit only, because Azure is read-only here");

await azTab.click();
await new Promise((r) => setTimeout(r, 60));

const azCreate = $(document, "create-body");
check(azCreate.textContent.includes("audited by this tool, not created by it"),
      "choosing it explains why there is nothing to fill in");
check(azCreate.querySelectorAll("input, select").length === 0,
      "and offers no form, rather than one that would 405");
check(!$(document, "create-live"),
      "with no live check either, there being nothing to check");

const azRow = document.querySelector("#list tr.clickable");
if (check(Boolean(azRow), "the account is listed")) {
  await azRow.click();
  await new Promise((r) => setTimeout(r, 60));

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

// ------------------------------------------------ where a resource goes

/* The one control that says where, and the two different things it means.

   This used to be a text box captioned "eastus, westeurope, uksouth…"
   repeated in all five Azure forms, sitting underneath a header control that
   said Region and was ignored by every Azure route it reached. The value now
   comes from one place, and place_field decides where it lands: in the spec
   for a cloud that puts location on the resource, nowhere for a cloud that
   puts it on the connection.

   Worth testing rather than reading, because the failure is silent. A spec
   with no location is refused by Azure with a message about the resource
   group, and a spec carrying a stale one builds the right thing in the wrong
   country. */

console.log("\nWhere a created resource goes");
console.log("-----------------------------");

const writableAzure = {
  key: "azure-storage", label: "Azure storage account",
  id_label: "Account name", read_only: false,
  only_ours_label: "only ones this tool made", provider: "azure",
};

const { window: w5, document: doc5, sent: sent5 } = await boot({
  "/resources": () => ({
    resources: [
      { key: "security-group", label: "Security group", id_label: "Group ID",
        read_only: false, only_ours_label: "only ones this tool made",
        provider: "aws" },
      writableAzure,
    ],
    providers: STUB_PROVIDERS,
  }),
  "/resources/azure-storage/options": () => ({ options: {} }),
  "/resources/azure-storage": (options) =>
    options.method === "POST"
      ? { resource_type: "azure-storage", resource_id: "demostore",
          problems: [], settings: {}, warnings: [],
          counts: { critical: 0, warning: 0, info: 0 } }
      : { resource_type: "azure-storage", resources: [] },
});

// AWS first: its region rides on the query string, because that is what the
// client is built from. A location in the spec as well would be a second copy
// in front of routes that do not read one.
const awsPost = await submitCreate(w5, doc5, sent5, { name: "demo-group" });
check(awsPost && awsPost.location === undefined,
      "an AWS spec carries no location, its region being on the connection");

const azurePos = [...$(doc5, "cloud").children]
  .find((b) => b.dataset.provider === "azure");
await azurePos.click();
await new Promise((r) => setTimeout(r, 60));

const azPost = await submitCreate(w5, doc5, sent5, { name: "demostore",
                                                    "resource group": "scp-demo" });

if (check(Boolean(azPost), "the Azure form submits")) {
  check(azPost.location === "eastus",
        "and its spec carries the location the header is showing");
  check(azPost.name === "demostore" && azPost.resource_group === "scp-demo",
        "alongside what was actually typed");
}

// Changing where, and having it stick to the resource rather than to nothing.
const placeSelect = $(doc5, "place");
placeSelect.value = "uksouth";
placeSelect.dispatchEvent(new w5.Event("change"));
await new Promise((r) => setTimeout(r, 60));

const movedPost = await submitCreate(w5, doc5, sent5, { name: "demostore",
                                                        "resource group": "scp-demo" });
check(movedPost && movedPost.location === "uksouth",
      "choosing another location sends that one, not the default");

/* Each cloud remembers where it was pointed. Switching to Azure to look at
   something and back should not quietly move an AWS resource from London to
   Virginia - which is what a single shared region would do, silently, at the
   moment of creating it. */
const awsPos = [...$(doc5, "cloud").children]
  .find((b) => b.dataset.provider === "aws");
await awsPos.click();
await new Promise((r) => setTimeout(r, 60));

check($(doc5, "place").value === "us-east-1",
      "the other cloud kept its own place while that one moved");

await azurePos.click();
await new Promise((r) => setTimeout(r, 60));

check($(doc5, "place").value === "uksouth",
      "and coming back finds the location that was chosen, not the default");

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
