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
function fakeApi(overrides = {}) {
  const sent = [];

  const routes = {
    "/health": () => ({ status: "ok" }),
    "/resources": () => ({
      resources: [
        { key: "security-group", label: "Security group",
          id_label: "Group ID", read_only: false },
        { key: "snapshot", label: "Disk backup",
          id_label: "Snapshot ID", read_only: true },
        { key: "alarm", label: "Alarm", id_label: "Alarm name",
          read_only: false },
      ],
    }),
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
check($(document, "types").children.length === 3,
      "a tab appears for every resource type the API advertises");
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
check($(doc2, "only-ours").disabled,
      "and 'only ones this tool made' is disabled, being meaningless there");

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

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
