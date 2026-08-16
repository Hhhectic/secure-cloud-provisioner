"use strict";

/* Talks to the same origin it was served from, so there is no API host to
   configure and no CORS involved. The backend serves this directory at /ui.

   Nothing here decides what is safe. Every refusal, every severity and every
   confirmation requirement comes from the API, because a rule enforced in a
   browser is a rule anyone can skip with curl. The one thing this file does
   insist on is that a forced delete cannot be reached without the plan being
   fetched and shown first - not as a safety mechanism, but so the person
   clicking has seen what the server is about to be asked to destroy. */

const API = "..";

const state = { types: [], type: null, tab: "dashboard", cloud: "aws",
                region: "us-east-1", options: {}, createInputs: null,
                /* What the last dashboard scan found, per type.
                   `{ [typeKey]: { at: Date, byId: Map<id, counts> } }`

                   Scanning is something you set going, and the tab you read
                   the answers on is a different place from the button that
                   starts it. So the Audit list no longer scans: it shows what
                   the dashboard found, and says plainly when that is nothing
                   yet rather than printing a verdict nobody asked for.

                   Cleared per type whenever something in that type is
                   created, fixed or deleted, because a cached verdict about a
                   resource that has since changed is worse than no verdict -
                   it is a wrong one with a timestamp on it. */
                scans: {} };

// The blueprint's sidebar key. Deliberately not a resource type: it composes
// six of them and the registry has no entry for it, so nothing must ever ask
// the server for /resources/blueprint.
const BLUEPRINT = "blueprint";

// Regions this tool is plausibly pointed at. Not fetched: DescribeRegions is
// an extra call and an account's enabled regions rarely surprise anyone.
const REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-central-1",
  "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-south-1",
  "ca-central-1", "sa-east-1",
];

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- plumbing

async function api(path, options = {}) {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(`${API}${path}${sep}region=${encodeURIComponent(state.region)}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  let body = null;
  try { body = await res.json(); } catch { /* 204s and empty bodies */ }

  if (!res.ok) {
    const detail = body && body.detail;
    const err = new Error(
      typeof detail === "string" ? detail
        : detail && detail.message ? detail.message
        : `HTTP ${res.status}`
    );
    err.status = res.status;
    err.detail = detail;
    throw err;
  }
  return body;
}

/* The same request, read a line at a time.

   `onStep` is called with each progress line as the server produces it, and
   the final object is returned like api() would. A cascade delete spends four
   or five minutes inside one request, and before this the page showed nothing
   for the whole of it - which is what somebody waiting cannot tell apart from
   a hang, and reported as one.

   Falls back to reading the whole body when there is no stream to read. That
   is not defensive padding: the jsdom suite replaces fetch with a stub that
   answers a plain object, and a page that only worked against a real
   streaming server would be untestable there. */
async function apiStream(path, options = {}, onStep = () => {}) {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(`${API}${path}${sep}region=${encodeURIComponent(state.region)}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok || !res.body || !res.body.getReader) {
    // A refusal still arrives as one JSON object with a status on it, because
    // everything that can refuse this does so before the stream begins.
    let body = null;
    try { body = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      const detail = body && body.detail;
      const err = new Error(
        typeof detail === "string" ? detail
          : detail && detail.message ? detail.message
          : `HTTP ${res.status}`);
      err.status = res.status;
      err.detail = detail;
      throw err;
    }
    return body;
  }

  const reader = res.body.getReader();
  const decode = new TextDecoder();
  let pending = "";
  let last = null;

  // A chunk boundary lands wherever the network puts it, so the tail of a
  // read is usually half a line. It is held back until the newline arrives.
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += decode.decode(value, { stream: true });

    const lines = pending.split("\n");
    pending = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      const parsed = JSON.parse(line);
      if (parsed.step) onStep(parsed.step);
      else last = parsed;
    }
  }
  if (pending.trim()) last = JSON.parse(pending);

  if (last && last.ok === false) throw new Error(last.message);
  return last;
}

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.className = isError ? "err" : "";
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 6000);
}

function text(tag, content, className) {
  const el = document.createElement(tag);
  el.textContent = content;
  if (className) el.className = className;
  return el;
}

/* A block of commands, with a button that puts them on the clipboard.

   The bastion's connect and teardown steps were rendered as a <pre> and left
   there, which meant the one path this tool recommends - generate the keys in
   the browser, build from the page - ended in transcribing six commands by
   hand from a screen. Every one of them carries a generated key filename or
   an address, so a typo is silent until ssh fails on something that looks
   right. */
function commandBlock(lines) {
  const wrap = document.createElement("div");
  const body = lines.join("\n");
  const pre = text("pre", body, "mono-block");

  const copy = document.createElement("button");
  copy.className = "quiet";
  copy.textContent = "Copy";
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(body);
      toast("Copied.");
    } catch {
      // A page served over plain HTTP on a machine without clipboard
      // permission cannot write to it, and failing silently would look like
      // the button doing nothing.
      const range = document.createRange();
      range.selectNodeContents(pre);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast("Clipboard unavailable — the text is selected, copy it.", true);
    }
  };

  wrap.append(pre, copy);
  return wrap;
}

/* A menu of known answers plus an escape hatch.

   Everything the tool already knows becomes a choice, and "Other…" reveals a
   text box for the cases it does not. Free text as the only option is a quiz:
   a box wanting a vpc- identifier, or captioned "from" and "to", asks the
   person to already know the answer before the form can help them find it. */
function choice(options, { allowOther = true, blank = "— choose —", other = "Other…" } = {}) {
  const wrap = document.createElement("span");
  const select = document.createElement("select");
  const free = document.createElement("input");
  free.className = "hidden";
  free.size = 22;

  // blank: null means the field has a sensible default and does not need an
  // empty first row. Passing a caption here that also appears in the options
  // is how the protocol menu ended up listing TCP twice.
  if (blank !== null) select.append(new Option(blank, ""));
  for (const o of options) select.append(new Option(o.label, o.value));
  if (allowOther) select.append(new Option(other, "__other__"));

  select.onchange = () => {
    const isOther = select.value === "__other__";
    free.classList.toggle("hidden", !isOther);
    if (isOther) free.focus();
  };

  wrap.append(select, free);
  wrap.value = () => (select.value === "__other__" ? free.value.trim()
                                                   : select.value);
  wrap.set = (v) => { select.value = v; };
  return wrap;
}

function multiChoice(options) {
  const select = document.createElement("select");
  select.multiple = true;
  select.size = Math.min(Math.max(options.length, 2), 5);
  for (const o of options) select.append(new Option(o.label, o.value));
  select.value = () => [...select.selectedOptions].map((o) => o.value);
  return select;
}

// ------------------------------------------------------------------ header

async function checkHealth() {
  const pill = $("health");
  try {
    await api("/health");
    pill.textContent = "API up";
    pill.className = "pill ok";
  } catch {
    pill.textContent = "API unreachable";
    pill.className = "pill bad";
  }
}

/* Which cloud the page is pointed at.

   Whether a cloud is reachable is not a property of the page but of what the
   server answers, so this only ever reports what the last list call said. An
   Azure without credentials answers 503 with a sentence naming the four
   variables, and that sentence is better than anything invented here. */
function setCloud(cloud, { repaint = true } = {}) {
  state.cloud = cloud;
  document.body.classList.toggle("cloud-azure", cloud === "azure");
  if (cloud === "aws") {
    checkHealth();
  } else {
    // Left saying "checking…" until the first list call answers, rather than
    // asserting reachability the page has no evidence for yet.
    $("health").textContent = "checking…";
    $("health").className = "pill";
  }
  renderScope();

  /* `repaint` is false exactly once: during boot, where loadTypes calls
     selectTab immediately afterwards and that repaints anyway.

     Without it the page loaded the current tab twice. On the dashboard, which
     now scans as it opens, that was eighteen scan requests for nine types -
     every resource in the account judged twice on every page load, against a
     real account, for nothing. Found by counting requests in a browser after
     a test insisted there should be one per type. */
  if (!repaint) return;

  // Switching cloud on the dashboard reloads the dashboard, not the picker.
  // Repainting a hidden sidebar and leaving the visible panel showing the
  // other account's counts is how "which cloud am I looking at" becomes a
  // question again, which is what the toggle exists to answer.
  if (state.tab === "dashboard") loadDashboard();
  else renderTypes();
}

/* What the header pill says about the cloud in front of you.

   For AWS that is /health, which answers for the process. Azure has no
   equivalent and should not get one: the process being up says nothing about
   whether a subscription is configured, and the only honest evidence is
   whether a real read just worked. A 503 there is the specific case worth
   naming, because it means the credentials are missing rather than the
   subscription being empty - and those two look identical in a list. */
function reportCloudReach(ok, error) {
  if (state.cloud !== "azure") return;
  const pill = $("health");
  if (ok) {
    pill.textContent = "subscription reachable";
    pill.className = "pill ok";
  } else if (error && error.status === 503) {
    pill.textContent = "not configured";
    pill.className = "pill bad";
  } else {
    pill.textContent = "subscription unreachable";
    pill.className = "pill bad";
  }
}

/* Which cloud a type belongs to, defaulted rather than required.

   The API sends this for every type and a test pins that it does. The default
   is here because the failure without one is silent and total: a type whose
   provider does not match is skipped, so a server that stopped sending the
   field would render an empty sidebar and no error - the page would look like
   an account with nothing in it. */
function providerOf(t) { return t.provider || "aws"; }

function cloudsPresent() {
  const seen = [];
  for (const t of state.types) {
    const p = providerOf(t);
    if (!seen.includes(p)) seen.push(p);
  }
  return seen;
}

/* The strip under the header: what "where" means for this cloud.

   An AWS region and an Azure location are not the same idea wearing two
   names. A region is chosen once and every call inherits it; an Azure
   resource carries its own location and its resource group, and asking for
   one up here would be a control that decides nothing. The region selector
   used to sit above the Azure tabs saying us-east-1 at a subscription that
   has never heard of it. */
function renderScope() {
  const box = $("scope-box");
  const note = $("scope-note");
  box.replaceChildren();

  if (state.cloud === "aws") {
    const select = document.createElement("select");
    select.id = "region";
    for (const r of REGIONS) select.append(new Option(r, r));
    select.value = state.region;
    // Changing region changes what every menu in the create form can offer,
    // so the form is rebuilt rather than left showing another region's
    // networks.
    select.onchange = () => {
      state.region = select.value;
      buildCreateForm();
      loadList();
    };
    box.append(document.createTextNode("Region "), select);
    note.textContent =
      "This talks to a real AWS account. Creating and deleting here does " +
      "the same thing it does from the command line.";
    return;
  }

  note.textContent =
    "This talks to a real Azure subscription. A location belongs to each " +
    "resource rather than to the connection, so there is no region to " +
    "choose here — creating asks for a resource group and a location.";
}

// ------------------------------------------------------------------- types

async function loadTypes() {
  const body = await api("/resources");
  state.types = body.resources;

  const clouds = cloudsPresent();
  $("cloud-toggle").classList.toggle("hidden", clouds.length < 2);
  setCloud(clouds.includes(state.cloud) ? state.cloud : (clouds[0] || "aws"),
           { repaint: false });
  selectTab(state.tab);
}

/* One cloud's types, plus the blueprint where there is one.

   The blueprint is not a resource type and the registry does not know about
   it, so it is added here as a key nothing on the server will ever be asked
   for. It used to be a panel rendered under every tab, including the five
   Azure ones, where it advertised an AWS architecture at a subscription that
   cannot build it. */
/* Which tab a resource type belongs on.

   Create is where things begin and Audit is where you look at what exists, so
   a type that cannot be created has no business on the Create tab - a form
   that always answers 405 is an advertised endpoint that can never work,
   which is the reasoning `read_only` already carries on the server.

   Everything appears under Audit, creatable or not. Scanning a bucket you
   made a minute ago and auditing a role you did not are the same activity. */
function belongsOn(type, tab) {
  if (tab === "audit") return true;
  if (tab === "create") return !type.read_only;
  return false;
}

/* Which panels each tab is made of.

   The sections are laid out once in index.html and shown or hidden, rather
   than moved between tabs. Moving them would mean re-creating the create form
   and re-fetching the list on every tab change, and the form is the one thing
   on this page somebody may have half-filled in. */
const PANELS = {
  dashboard: ["dashboard"],
  create: ["create"],
  audit: ["listing", "detail"],
};

function selectTab(name) {
  state.tab = name;

  for (const b of $("tabs").children) {
    const on = b.dataset.tab === name;
    b.classList.toggle("active", on);
    b.setAttribute("aria-selected", String(on));
  }

  // The blueprint builds six resources, so it is a Create thing and is
  // reached from the sidebar there. It hides itself here and selectType puts
  // it back when it is the chosen entry.
  $("blueprint").classList.add("hidden");
  for (const id of ["dashboard", "listing", "detail", "create"]) {
    $(id).classList.toggle("hidden", !(PANELS[name] || []).includes(id));
  }

  // The dashboard is about the whole account rather than one type, so it has
  // no use for a resource picker and the region control means nothing there.
  const picking = name !== "dashboard";
  $("sidebar").classList.toggle("hidden", !picking);
  document.body.classList.toggle("no-picker", !picking);
  $("side-head").textContent = name === "create" ? "Make" : "Inspect";

  // The region control belongs to a request about a resource. The dashboard
  // asks about every type at once and the scope note underneath it talks
  // about creating and deleting, neither of which happens there.
  $("scope-box").classList.toggle("hidden", !picking);

  if (name === "dashboard") {
    loadDashboard();
    return;
  }
  renderTypes();
}

function renderTypes() {
  const nav = $("types");
  nav.replaceChildren();

  for (const t of state.types) {
    if (providerOf(t) !== state.cloud) continue;
    if (!belongsOn(t, state.tab)) continue;
    const b = document.createElement("button");
    b.dataset.key = t.key;
    b.append(text("span", t.short_label || t.label));
    if (t.read_only) b.append(text("span", "audit", "tag"));
    b.onclick = () => selectType(t.key);
    nav.append(b);
  }

  // Six resources at once, and all of them AWS. It is a way of making things,
  // so it is offered where things are made.
  if (state.cloud === "aws" && state.tab === "create") {
    const b = document.createElement("button");
    b.dataset.key = BLUEPRINT;
    b.className = "set-apart";
    b.append(text("span", "Bastion architecture"), text("span", "six pieces", "tag"));
    b.onclick = () => selectType(BLUEPRINT);
    nav.append(b);
  }

  const first = nav.firstElementChild;
  const stillThere = [...nav.children].some((b) => b.dataset.key === state.type);
  if (!stillThere && first) selectType(first.dataset.key);
  else if (state.type) selectType(state.type);
}

function currentType() {
  return state.types.find((t) => t.key === state.type);
}

function selectType(key) {
  state.type = key;
  for (const b of $("types").children) {
    b.classList.toggle("active", b.dataset.key === key);
  }

  // The blueprint is six resources at once rather than one of anything, so it
  // replaces this tab's panels instead of appearing under them.
  const isBlueprint = key === BLUEPRINT;
  $("blueprint").classList.toggle("hidden", !isBlueprint);
  for (const id of PANELS[state.tab] || []) {
    $(id).classList.toggle("hidden", isBlueprint);
  }
  if (isBlueprint) {
    buildBlueprintPanel();
    return;
  }

  const known = currentType();
  $("audit-badge").classList.toggle("hidden", !known.read_only);
  $("detail-id").textContent = "";
  resetDetail();

  // Only the work this tab actually shows. Building the form while the Audit
  // tab is open fetches that type's option menus - every machine size the
  // subscription can start, which is a five to eight second call - to fill in
  // a form nobody can see.
  if (state.tab === "create") buildCreateForm();
  if (state.tab === "audit") loadList();
}

// --------------------------------------------------------------- dashboard

/* What exists, and what this tool has been doing.

   Deliberately not a scan. Counting what is in the account is one call per
   type and answers in a second; judging it is seven AWS calls per bucket,
   one after another, which CLAUDE.md already records as visibly slow past a
   demo account. A landing page that takes a minute is a landing page people
   learn to skip, so the posture is behind a button and arrives per type as
   each answer lands.

   The two are kept visibly apart. A type that has not been scanned says so
   rather than showing a zero, because "nothing found" and "nothing looked
   for" are the one confusion this tool cannot afford - it is the same bug the
   list had on its first load, where every row read as clean because
   worst_level is null in both cases. */
async function loadDashboard() {
  const body = $("dash-body");
  body.replaceChildren(text("p", "Loading…", "muted"));

  const mine = state.types.filter((t) => providerOf(t) === state.cloud);

  const grid = document.createElement("div");
  grid.className = "dash-grid";
  const cards = {};

  for (const t of mine) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "dash-card";
    card.append(text("div", t.short_label || t.label, "dash-name"));
    card.append(text("div", "—", "dash-count"));
    card.append(text("div", "counting…", "dash-state"));
    // The dashboard is a way in, not a dead end: a card is the resource it
    // names, so clicking one opens it where it can be acted on.
    //
    // The type is set before the tab changes, because selectTab renders the
    // picker and picks the first entry when the current one is not in it -
    // so doing it the other way round loaded a type nobody asked for and
    // then loaded this one on top, two requests for one click.
    card.onclick = () => { state.type = t.key; selectTab("audit"); };
    cards[t.key] = card;
    grid.append(card);
  }

  body.replaceChildren();

  /* One sentence saying how the account stands.

     The grid answers "how many of each", which took nine cards to add up into
     the thing somebody actually came to find out. This says it once, at the
     top, and the cards below it are the breakdown.

     It is filled in by the scan, not by the count, and says so until then -
     the whole panel turns on never printing a verdict before the question has
     been asked. */
  const verdict = document.createElement("div");
  verdict.className = "verdict";
  verdict.append(text("p", "Reading this account…", "verdict-line"));
  body.append(verdict);

  body.append(text("h3", "What is in this account"));
  body.append(grid);

  // Under the cards, not beside the heading. It describes every one of them,
  // and sitting next to the title it read as a caption on the title - and
  // pushed that title off its own line as the time got longer.
  body.append(text("p", "counting…", "scan-when"));

  const activity = document.createElement("div");
  body.append(text("h3", "Recent activity"));
  body.append(activity);
  loadActivity(activity);

  // One request per type, all at once. The server does each list serially
  // inside itself; firing them together is what keeps the whole grid to about
  // the time of its slowest type rather than the sum of all of them.
  await Promise.all(mine.map(async (t) => {
    const card = cards[t.key];
    try {
      const found = await api(`/resources/${t.key}?only_ours=false&with_scan=false`);
      const n = (found.resources || []).length;
      card.querySelector(".dash-count").textContent = String(n);
      card.querySelector(".dash-state").textContent =
        n === 0 ? "none" : "not scanned";
      card.dataset.count = String(n);
    } catch (e) {
      card.querySelector(".dash-count").textContent = "—";
      card.querySelector(".dash-state").textContent = "unreachable";
      card.classList.add("unreachable");
      card.title = e.message;
    }
  }));

  reportCloudReach(!Object.values(cards).every((c) => c.classList.contains("unreachable")));

  /* And then judge them, without being asked.

     This was a button on the reasoning that scanning is the slow path - seven
     AWS calls per bucket, one after another, which this repository records as
     visibly slow past a demo account. Measured rather than assumed: 3.4
     seconds for the whole AWS account and 3.6 for the whole subscription,
     because the types are asked in parallel and only the resources within one
     type are serial.

     Three seconds is not a reason to make somebody press a button, and the
     card that says "not scanned" is a card that has not answered the question
     the page exists to answer. The counts are drawn first and the verdicts
     land on top of them, so nothing waits on the scan to be readable. */
  scanEverything();
}

/* Fills in the posture, per type, as each answer arrives.

   Run on load and again on demand. Each type is asked in parallel and every
   card updates the moment its own type comes back, so the grid takes about
   the time of its slowest type rather than the sum of all of them - which is
   what makes a whole account three seconds instead of thirty. */
async function scanEverything() {
  const button = $("scan-all");
  button.disabled = true;
  button.textContent = "Scanning…";

  const when = $("dash-body").querySelector(".scan-when");
  if (when) when.textContent = "scanning…";

  const headline = $("dash-body").querySelector(".verdict-line");
  if (headline) headline.textContent = "Scanning…";

  const mine = state.types.filter((t) => providerOf(t) === state.cloud);
  const cards = [...$("dash-body").querySelectorAll(".dash-card")];
  const byName = new Map(cards.map((c) =>
    [c.querySelector(".dash-name").textContent, c]));

  for (const card of cards) card.querySelector(".dash-state").textContent = "scanning…";

  // What the headline is made of. Unreachable is counted separately and on
  // purpose: a type that could not be read is not a type with nothing wrong
  // in it, and the difference is the one this tool must never blur.
  const total = { critical: 0, warning: 0, resources: 0, unreachable: [] };

  await Promise.all(mine.map(async (t) => {
    const card = byName.get(t.short_label || t.label);
    if (!card) return;
    try {
      const found = await api(`/resources/${t.key}?only_ours=false&with_scan=true`);
      const rows = found.resources || [];
      let critical = 0, warning = 0;

      // Kept per resource, not just totalled. This is the only scan the page
      // runs over a whole type, so the Audit tab reads its answers rather
      // than asking for them again - which is what lets that tab be a place
      // findings are read instead of a place they are fetched.
      const byId = new Map();
      for (const r of rows) {
        if (!r.counts) continue;
        byId.set(r.id, r.counts);
        critical += r.counts.critical || 0;
        warning += r.counts.warning || 0;
      }
      state.scans[t.key] = { at: new Date(), byId };

      total.critical += critical;
      total.warning += warning;
      total.resources += rows.length;

      // Both numbers where there are both. "2 critical" alone on a type that
      // also has nine warnings is a true sentence that hides the larger half,
      // and the point of the card is to be read without opening it.
      const parts = [];
      if (critical) parts.push(`${critical} critical`);
      if (warning) parts.push(`${warning} warning`);

      const where = card.querySelector(".dash-state");
      where.textContent = rows.length === 0 ? "none"
        : parts.length ? parts.join(", ")
        : "clean";
      card.classList.toggle("has-critical", critical > 0);
      card.classList.toggle("has-warning", !critical && warning > 0);
      card.classList.toggle("clean", rows.length > 0 && !critical && !warning);
    } catch (e) {
      total.unreachable.push(t.short_label || t.label);
      card.querySelector(".dash-state").textContent = "unreachable";
      card.classList.add("unreachable");
    }
  }));

  if (headline) renderVerdict(headline, total);

  if (when) {
    when.textContent =
      `since last scan, ${new Date().toLocaleTimeString()}`;
  }
  button.disabled = false;
  button.textContent = "Scan again";
}

/* How the account stands, in one sentence.

   The wording is the whole of this function and it is the part that can go
   wrong quietly. Three rules it must not break:

   A type that could not be read is not a type with nothing wrong in it. If
   anything was unreachable the headline says so and never claims the account
   is clean, because a partial scan that reads as a pass is the one way this
   tool can actively mislead - the same rule the IAM scanner states and the
   list learned the hard way.

   An empty account is not a safe one, it is an empty one. "Nothing to report"
   where there is nothing to report at all would be read as a verdict on
   resources that do not exist.

   And warnings are not hidden behind a clean bill on criticals. No criticals
   with fourteen warnings is good news and unfinished news, so it says both. */
function renderVerdict(into, total) {
  const parent = into.parentElement;
  parent.classList.remove("is-critical", "is-warning", "is-clean");
  into.replaceChildren();

  const say = (main, level, note) => {
    into.textContent = main;
    if (level) parent.classList.add(level);
    if (note) {
      const p = text("p", note, "verdict-note");
      parent.append(p);
    }
  };

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const missed = total.unreachable.length
    ? `${plural(total.unreachable.length, "type")} could not be read `
      + `(${total.unreachable.join(", ")}), so this is not the whole account.`
    : null;

  if (total.critical) {
    say(plural(total.critical, "critical finding"), "is-critical",
        [total.warning ? `${plural(total.warning, "warning")} as well.` : null,
         missed].filter(Boolean).join(" "));
    return;
  }

  if (total.warning) {
    say(`No critical findings, ${plural(total.warning, "warning")}`,
        "is-warning", missed);
    return;
  }

  if (total.unreachable.length) {
    // Nothing found, and not everything looked at. That is not a clean
    // account; it is an unfinished scan, and it says the second thing.
    say("Scan incomplete", null, missed);
    return;
  }

  if (!total.resources) {
    say("Nothing in this account yet", null,
        "No resources of any type, so there is nothing to judge.");
    return;
  }

  say("Nothing critical or warning", "is-clean",
      `Across ${plural(total.resources, "resource")}.`);
}

async function loadActivity(into) {
  into.replaceChildren(text("p", "Loading…", "muted"));
  let body;
  try {
    body = await api("/activity?limit=12");
  } catch (e) {
    into.replaceChildren(text("p", e.message, "muted"));
    return;
  }

  const entries = body.activity || [];
  if (!entries.length) {
    // Not an error, and worth saying which. A tool that has changed nothing
    // has an empty log, and so does one whose log cannot be written.
    into.replaceChildren(text("p",
      "Nothing yet. This records what the tool changed and what it refused " +
      "to do — the refusals leave no trace anywhere else, because nothing " +
      "happened.", "muted"));
    return;
  }

  const list = document.createElement("ul");
  list.className = "activity";
  for (const e of entries) {
    const li = document.createElement("li");
    li.append(text("span", e.outcome || "—", `outcome ${e.outcome || ""}`));
    li.append(text("span", `${e.method || ""} ${e.path || ""}`.trim(), "what"));
    li.append(text("span", (e.at || "").replace("T", " ").slice(0, 19), "when"));
    if (e.why) li.append(text("span", e.why, "why"));
    list.append(li);
  }
  into.replaceChildren(list);
}

// ----------------------------------------------------------------- listing

/* The detail panel with nothing chosen.

   Written three times as a bare "Pick something from the list." - which is
   an instruction with no information in it, on the largest empty area of the
   page. It says what the panel is for now, which is the thing somebody who
   has not clicked a row yet does not know. */
function resetDetail() {
  const waiting = document.createElement("div");
  waiting.className = "nothing";
  waiting.append(text("p", "Nothing selected.", "nothing-line"));
  waiting.append(text("p",
    "Pick a row above to see what it is, what is wrong with it, and what "
    + "this tool can fix without being told how.", "nothing-note"));
  $("detail-body").replaceChildren(waiting);
}

async function loadList() {
  const known = currentType();
  $("listing-title").textContent = known.short_label || known.label;

  /* Which type this call is about, remembered before the first await.

     Two loads can be in flight at once - opening the Audit tab selects the
     first type and a dashboard card then selects a different one - and the
     slower answer used to render whatever came back against whichever type
     was current by then. That produced a list of one type's resources under
     another type's cached verdicts, so every row read "not scanned" beneath
     a note saying when the scan had been taken. Both halves were true and
     they were about different things. */
  const forType = state.type;

  const list = $("list");
  list.replaceChildren(text("p", "Loading…", "muted"));

  /* Everything in the account, and never a scan.

     only_ours is false rather than a checkbox. It defaulted to true, so this
     tab quietly answered a narrower question than the Dashboard beside it -
     whose counts have always been every resource - and the same account read
     as two different accounts depending which tab you were on. An audit that
     hides what this tool did not create is also the wrong default outright:
     the resources somebody else made are the ones nobody has looked at.

     with_scan is false because this tab reads and the Dashboard scans. The
     verdicts come from state.scans; a list that scanned on open was a minute
     of waiting nobody asked for. */
  let body;
  try {
    body = await api(`/resources/${forType}?only_ours=false&with_scan=false`);
    reportCloudReach(true);
  } catch (e) {
    if (state.type !== forType) return;
    reportCloudReach(false, e);
    list.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  // Somebody has moved on since this was asked for. Rendering it now would
  // overwrite the list they are actually looking at.
  if (state.type !== forType) return;

  renderCleanup(known);

  /* An empty list says what is empty, and what that does not mean.

     "Nothing here." sat under a heading naming one resource type, in a tool
     whose whole job is finding what is wrong, and read as a clean bill on the
     account. It is not one: it says this account holds no resources of this
     one kind, which for eleven of the fourteen types is the ordinary state of
     a demo account and says nothing at all about the other thirteen. */
  if (!body.resources.length) {
    const nothing = document.createElement("div");
    nothing.className = "nothing";
    nothing.append(text("p",
      `No ${(known.short_label || known.label).toLowerCase()} in this ` +
      `${state.cloud === "azure" ? "subscription" : "account"}.`, "nothing-line"));
    nothing.append(text("p",
      known.read_only
        ? "Nothing to audit here. The other types are unaffected — this is "
          + "about this one kind of resource, not about the account."
        : "That is a fact about this one kind of resource, not a verdict on "
          + "the account. The Create tab makes one.", "nothing-note"));
    list.replaceChildren(nothing);
    return;
  }

  const scan = state.scans[state.type];

  /* A Name column only where a name is not the id.

     For a bucket, a storage account and every Azure type the id *is* the
     name, so the table printed "richard-huo-resume-2026" twice across two
     headed columns and spent a fifth of the width saying the same thing
     again. Security groups and machines have both and keep both. */
  const named = body.resources.some((r) => r.name && r.name !== r.id);

  const table = document.createElement("table");
  const head = document.createElement("tr");
  const columns = named
    ? [known.id_label, "Name", "Worst", "Findings", ""]
    : [known.id_label, "Worst", "Findings", ""];
  for (const h of columns) head.append(text("th", h));
  table.append(head);

  for (const r of body.resources) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.onclick = () => showDetail(r.id);

    tr.append(text("td", r.id));
    if (named) tr.append(text("td", r.name || ""));

    // Not scanned is not clean, and that has not changed by moving where the
    // scan is started. counts is the signal, because worst_level is null for
    // both "nothing was found" and "nothing was looked for"; printing a
    // verdict on the second labelled a storage account with two critical
    // findings clean.
    const counts = scan && scan.byId.get(r.id);
    const worst = counts && (counts.critical ? "critical"
      : counts.warning ? "warning"
      : counts.info ? "info" : "clean");

    const verdict = text("td", r.unreachable ? "?"
      : !counts ? "not scanned"
      : worst);
    if (counts && worst !== "clean") verdict.className = `worst ${worst}`;
    tr.append(verdict);

    tr.append(text("td", counts
      ? `${counts.critical} critical, ${counts.warning} warning, ${counts.info} info`
      : (r.unreachable || "—")));

    const actions = document.createElement("td");
    if (!known.read_only) {
      const del = document.createElement("button");
      del.textContent = "Delete";
      del.className = "danger";
      del.onclick = (ev) => { ev.stopPropagation(); startDelete(r.id); };
      actions.append(del);
    }
    tr.append(actions);
    table.append(tr);
  }

  list.replaceChildren();

  /* Where the verdicts came from, and when.

     Without this the Worst column is an assertion with no provenance: a row
     saying "clean" cannot be told from one scanned before somebody changed
     the thing. Saying when is what makes an unscanned list obviously
     unanswered rather than quietly reassuring - which is the one way this
     tool can actively mislead, and the reason a scan is never implied. */
  const provenance = document.createElement("p");
  provenance.className = "muted scan-note";
  if (!scan) {
    provenance.append(document.createTextNode(
      "These have not been scanned. Findings load when you open one; to judge "
      + "them all at once, "));
    const go = document.createElement("button");
    go.className = "link";
    go.textContent = "scan from the Dashboard";
    go.onclick = () => { selectTab("dashboard"); scanEverything(); };
    provenance.append(go, document.createTextNode("."));
  } else {
    provenance.textContent =
      `Verdicts from the scan at ${scan.at.toLocaleTimeString()}. Anything ` +
      "changed since is judged again when you open it.";
  }
  list.append(provenance, table);
}

/* Forgets a type's cached verdicts.

   Called wherever this tool changes something. A verdict about a resource
   that has since been fixed, created or destroyed is not merely old - it is
   wrong, and it is wrong while carrying a timestamp that makes it look
   checked. */
function forgetScan(typeKey) {
  delete state.scans[typeKey || state.type];
}

function renderCleanup(known) {
  const box = $("cleanup-box");
  box.replaceChildren();
  if (known.read_only) return;

  const b = document.createElement("button");
  // short_label, because the toggle has already said which cloud this is
  // and "every azure network security group" repeats it in a sentence.
  const what = (known.short_label || known.label).toLowerCase();
  b.textContent = `Clean up every ${what} this tool made`;
  b.className = "danger";
  b.onclick = () => startCleanup(known);

  const row = document.createElement("div");
  row.className = "row";
  row.append(b);
  box.append(row);
}

// ------------------------------------------------------------------ detail

async function showDetail(id) {
  const known = currentType();
  const body = $("detail-body");
  body.replaceChildren(text("p", "Reading…", "muted"));

  let data;
  try {
    data = await api(`/resources/${state.type}/${encodeURIComponent(id)}`);
  } catch (e) {
    body.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  body.replaceChildren();
  // The id moves up into the card's own heading rather than repeating as the
  // first line of its contents.
  $("detail-id").textContent = `${known.id_label}: ${id}`;

  body.append(text("h3", "Findings"));
  if (!data.warnings.length) {
    /* The one empty state here that *is* a verdict, and it has been earned:
       this resource was read just now and every rule ran over it. Saying so
       is the difference between this and the list above, where nothing found
       means nothing of that kind exists. */
    const clean = document.createElement("div");
    clean.className = "nothing is-clean";
    clean.append(text("p", "Nothing to report.", "nothing-line"));
    clean.append(text("p",
      `Every rule this tool has for a ${(known.short_label || known.label)
        .toLowerCase()} ran over this one and none of them fired. What it is `
      + "made of is below.", "nothing-note"));
    body.append(clean);
  } else {
    renderFindingGroups(body, data.warnings, data.counts, id);
  }

  /* The raw settings, folded away.

     This is what the resource *is*, as opposed to what is wrong with it, and
     it is worth keeping - the scanner's verdict is only checkable against the
     thing it judged. But a bucket's settings run to forty lines of JSON, so
     open by default it was the largest thing on the panel and the findings
     above it scrolled away beneath it. Findings first; the evidence is one
     click under them. */
  const what = document.createElement("details");
  what.className = "what-it-is";
  what.append(text("summary", "What it is"));
  what.append(text("pre", JSON.stringify(data.settings, null, 2), "mono-block"));
  body.append(what);
}

/* The severity counts, as tallies rather than a sentence.

   A level with nothing in it is drawn flat and grey rather than dropped. The
   absence of criticals is a finding in itself, and a row that silently omits
   the level you were looking for cannot be told from one that never checked -
   which is the failure this project names as the only way the tool can
   actively mislead. */
function renderFindingGroups(body, warnings, counts, resourceId) {
  const LEVELS = ["critical", "warning", "info"];
  const named = { critical: "critical", warning: "warning", info: "informational" };

  const grouped = { critical: [], warning: [], info: [] };
  for (const w of warnings) (grouped[w.level] || grouped.info).push(w);

  const tallies = document.createElement("div");
  tallies.className = "tallies";
  const panels = document.createElement("div");

  // Every level's setter, so opening one can shut the rest.
  const openers = [];

  for (const level of LEVELS) {
    const found = grouped[level];

    const panel = document.createElement("div");
    panel.className = "group";
    panel.id = `findings-${level}`;
    for (const w of found) panel.append(renderFinding(w, resourceId));

    const tally = document.createElement("button");
    tally.type = "button";
    tally.className = `tally ${level}` + (found.length ? "" : " empty");
    tally.setAttribute("aria-controls", panel.id);
    tally.append(text("span", String(counts[level] || 0), "n"));
    tally.append(text("span", named[level], "what"));

    // Criticals are open on arrival. Every other level starts shut, which is
    // what makes the criticals findable rather than the fourth thing down a
    // wall - but the most urgent thing this tool can say is never behind a
    // click. A finding is made quieter and never absent, and one nobody
    // expanded has been made absent whatever the counts say.
    const show = (open) => {
      panel.classList.toggle("open", open);
      tally.classList.toggle("open", open);
      tally.setAttribute("aria-expanded", String(open));
    };
    show(level === "critical" && found.length > 0);

    // An empty level is not a button. There is nothing behind it, and a
    // control that responds to a click by doing nothing teaches people that
    // clicks here do nothing.
    if (found.length) {
      tally.onclick = () => {
        // One level at a time. Two open drawers put a critical and a note on
        // screen at the same weight and leave the reader to work out where
        // one list ended, which is the wall this was built to remove - and
        // the counts stay visible whichever is open, so nothing is lost by
        // showing one of them.
        const opening = !panel.classList.contains("open");
        for (const other of openers) other(false);
        show(opening);
      };
    } else {
      tally.disabled = true;
      tally.setAttribute("aria-expanded", "false");
    }

    openers.push(show);
    tallies.append(tally);
    panels.append(panel);
  }

  // Accepted is a count, not a group, and so is not a button.
  //
  // An acknowledged finding keeps its level and its place in the list, so the
  // three criticals above may include two that somebody has already decided
  // on. Making this a fourth drawer would mean either listing those findings
  // twice or subtracting them from their own severity - and subtracting them
  // is exactly the "suppression that empties the screen" this project refuses
  // everywhere else.
  if (counts.acknowledged) {
    const accepted = document.createElement("div");
    accepted.className = "tally accepted";
    accepted.title =
      "Findings somebody has accepted. They are still counted at their own " +
      "severity above, and still listed there.";
    accepted.append(text("span", String(counts.acknowledged), "n"));
    accepted.append(text("span", "accepted", "what"));
    tallies.append(accepted);
  }

  body.append(tallies, panels);
}

function renderFinding(w, resourceId) {
  // Not folded itself. Its group is the fold, and folding a finding inside a
  // folded group means two clicks to read one sentence.
  const box = document.createElement("div");
  box.className = `finding ${w.level}`;
  if (w.acknowledged) box.classList.add("acknowledged");

  const level = text("div", w.level, "level");
  if (w.acknowledged) level.textContent += " — acknowledged";
  box.append(level);
  box.append(text("div", w.message));

  // Dimmed and labelled, never dropped. Something you cannot see is something
  // you cannot review, and the point of an acknowledgement is that somebody
  // decided to live with this, not that it stopped being true.
  if (w.acknowledged) {
    const a = w.acknowledged;
    box.append(text("div",
      `${a.by} accepted this${a.on ? " on " + a.on : ""}` +
      `${a.until ? ", until " + a.until : ""}: ${a.reason}`, "ack"));
  }

  if (w.control) {
    box.append(text("div",
      `${w.control.framework} v${w.control.version} §${w.control.id} (Level ${w.control.level})`,
      "cite"));
  }

  // A fix needs both halves. A finding with a fix but no rule_id describes
  // something that does not exist yet, which the API declines to act on.
  if (w.fix && w.rule_id) {
    const row = document.createElement("div");
    row.className = "row";

    const cidr = document.createElement("input");
    cidr.placeholder = "new source (optional, e.g. 203.0.113.4/32)";
    cidr.size = 34;

    const b = document.createElement("button");
    b.textContent = w.fix.label || "Fix";
    b.onclick = async () => {
      b.disabled = true;
      try {
        const payload = { rule_id: w.rule_id };
        if (cidr.value.trim()) payload.new_cidr = cidr.value.trim();
        const res = await api(
          `/resources/${state.type}/${encodeURIComponent(resourceId)}/fix`,
          { method: "POST", body: JSON.stringify(payload) }
        );
        toast(res.message);
        showDetail(resourceId);
        // What this just changed is no longer what the last scan judged.
        forgetScan();
        loadList();
      } catch (e) {
        toast(e.message, true);
        b.disabled = false;
      }
    };

    row.append(b, cidr);
    box.append(row);
  } else if (w.fix) {
    box.append(text("div",
      "Change this before creating it, or accept it knowingly.", "muted"));
  }

  // The identifier, and the form that accepts the finding.
  //
  // This used to build a JSON snippet and put it on the clipboard, because
  // the API had no write path by design - the file was edited and committed
  // by a person. It writes now, through POST /acknowledgements; see the
  // header of scanner/acknowledged.py for what that trades away and what
  // replaced it.
  //
  // Gated on resourceId for the same reason the fix button above is: a
  // pre-flight finding describes something that does not exist, and
  // acknowledging it would write an entry naming a resource that may never be
  // created - which the audit would then report as matching nothing. The
  // server refuses that case as well, on the stronger ground that it re-scans
  // and finds no such rule.
  if (resourceId && w.rule_id && !w.acknowledged) {
    box.append(acknowledgeForm(w, resourceId));
  }

  return box;
}

/* Accepting one finding, knowingly.

   Folded shut by default. An acknowledgement is meant to be a deliberate act,
   and a reason box sitting open under every finding is an invitation to make
   it a reflex.

   `by` is a blank rather than a guess: the browser does not know who is
   sitting in front of it, and a name this file invented would be worse
   provenance than one somebody typed. The CLI could read git config and no
   longer runs this, which is the one thing the move cost. */
function acknowledgeForm(w, resourceId) {
  const wrap = document.createElement("details");
  wrap.className = "ack-help";
  wrap.append(text("summary", `Accept this finding — ${w.rule_id}`));

  const body = document.createElement("div");
  body.append(text("p",
    "The finding keeps its severity and its place in this list. It is dimmed " +
    "and says who accepted it and why — nothing is hidden, and the counts " +
    "still include it.", "muted"));

  const reason = document.createElement("textarea");
  reason.rows = 2;
  reason.placeholder =
    "why this is intended, in a sentence somebody else can check";

  const by = document.createElement("input");
  by.placeholder = "your name";
  by.size = 18;

  // Six months out, which is scanner/acknowledged.DEFAULT_DAYS. Shown rather
  // than left implicit: an expiry nobody saw is one nobody expects to arrive.
  const until = document.createElement("input");
  until.type = "date";
  const default_until = new Date();
  default_until.setDate(default_until.getDate() + 180);
  until.value = default_until.toISOString().slice(0, 10);

  body.append(
    labelled("reason", reason),
    labelled("your name", by),
    labelled("expires", until),
  );

  const accept = document.createElement("button");
  accept.className = "quiet";
  accept.textContent = "Accept this finding";
  accept.onclick = async () => {
    accept.disabled = true;
    try {
      const res = await api("/acknowledgements", {
        method: "POST",
        body: JSON.stringify({
          resource_type: state.type,
          resource_id: resourceId,
          rule_id: w.rule_id,
          reason: reason.value.trim(),
          by: by.value.trim(),
          until: until.value || null,
          // Repeating the id is the server's demand, and it is satisfied here
          // rather than by a second box for somebody to retype it into. The
          // guard is against a request forged somewhere else, which would
          // have to know this id; it is not a test of whether the person
          // meant it, which the reason and the fold already ask.
          confirm: w.rule_id,
        }),
      });
      toast(res.message);
      showDetail(resourceId);
      // What this just changed is no longer what the last scan judged.
      forgetScan();
      loadList();
    } catch (e) {
      toast(e.message, true);
      accept.disabled = false;
    }
  };
  body.append(accept);

  wrap.append(body);
  return wrap;
}

// ------------------------------------------------------------------ create

// Only the fields each resource actually reads. The API takes one spec model
// for every type and each adapter ignores what does not apply to it, but
// showing a bucket a field about subnets would suggest it meant something.
/* What a field is called in the API, and what it should be called on screen.

   The spec field names belong to AWS and to the routes; "namespace" is a
   CloudWatch word for what a person would call "watch", and vpc_id is an
   identifier where the question is "which network". Anything absent here
   falls back to its own name with the underscores taken out, which is right
   for name, description and email. */
const LABELS = {
  namespace: "watch",
  threshold: "alert above",
  vpc_id: "network",
  cidr: "address range",
  security_group_ids: "firewalls",
  subnet_id: "subnet",
  instance_type: "size",
  key_name: "key pair",
  assign_public_ip: "give it a public address",
  with_nat_gateway: "add a NAT gateway",
  secure_by_default: "secure defaults",
  public_key: "public key",
  notify: "email me when it fires",
};

// kind is how the field is asked for. "menu" and "multi" are filled from
// GET /resources/{type}/options, so the choices come from the account and
// from the allowlists the tool already enforces.
const FIELDS = {
  "security-group": [
    ["name", "text", "a name for this group"],
    ["description", "text", "what it is for"],
    ["vpc_id", "menu", "which network it belongs to"],
    ["rules", "rules", ""],
  ],
  "bucket": [
    ["name", "text", "globally unique across all of AWS"],
    ["secure_by_default", "checkbox", true],
  ],
  "key-pair": [
    ["name", "text", "a name for this key"],
    ["public_key", "textarea", "ssh-ed25519 AAAA… — the PUBLIC half only",
     "Three parts separated by spaces. First the algorithm. Then the key " +
     "itself, base64 encoded — this is the only part that is cryptographic. " +
     "Last a comment, which is free text that SSH ignores; it is there so " +
     "you can tell your keys apart in a server's authorized_keys file, and " +
     "this tool puts the key's name in it. AWS does not store the comment. " +
     "Nothing here is secret: a public key is meant to be handed out."],
  ],
  "instance": [
    ["name", "text", "a name for this server"],
    ["instance_type", "menu", "size — the tool refuses anything larger"],
    ["key_name", "menu", "which imported key can log in"],
    ["security_group_ids", "multi", "which firewalls apply"],
    ["subnet_id", "menu", "where it sits — this decides its exposure"],
    ["assign_public_ip", "checkbox", false],
  ],
  "network": [
    ["name", "text", "a name for this network"],
    ["cidr", "menu", "address range"],
    ["with_nat_gateway", "checkbox", false],
  ],
  "alarm": [
    ["name", "text", "a name for this alarm"],
    // No hint on either of these: the caption asks the question and the
    // metric's own label carries the unit, so anything here would be a third
    // telling of the same thing.
    ["namespace", "menu", ""],
    ["threshold", "text", ""],
    ["email", "text", "where to send the alert",
     "AWS emails this address a confirmation link, and delivers nothing to " +
     "it until somebody clicks. An alarm whose only address never confirmed " +
     "is as silent as one with no address at all, and the scan reports that " +
     "separately once it exists."],
    ["notify", "checkbox", true],
  ],

  // The Azure types. Every one of them needs a resource group, which has no
  // AWS equivalent: Azure will not accept any resource without one, and there
  // is no account default to fall back on the way there is for a VPC. The
  // adapters in api/registry.py refuse rather than inventing a place to put
  // somebody's storage, so the field is required here for the same reason.
  //
  // Before these entries existed the page fell back to a name-only form for
  // anything unlisted, so every Azure create submitted without a group and was
  // refused - the one thing the API and the CLI could do that the page could
  // not.
  "azure-storage": [
    ["name", "text", "3-24 lowercase letters and numbers, globally unique"],
    ["resource_group", "text", "Azure needs one; it is created if it is new"],
    ["location", "text", "eastus, westeurope, uksouth…"],
    ["secure_by_default", "checkbox", true],
  ],
  "azure-keyvault": [
    ["name", "text", "3-24 letters, numbers and hyphens, starting with a letter"],
    ["resource_group", "text", "Azure needs one; it is created if it is new"],
    ["location", "text", "eastus, westeurope, uksouth…"],
    ["secure_by_default", "checkbox", true,
     "Secure here turns on purge protection, which can never be turned off " +
     "again. The vault and its name are then held for 90 days after any " +
     "delete, and nothing - including this tool - can shorten that. For " +
     "something you intend to throw away, leave this off."],
  ],
  "azure-nsg": [
    ["name", "text", "a name for this firewall"],
    ["resource_group", "text", "Azure needs one; it is created if it is new"],
    ["location", "text", "eastus, westeurope, uksouth…"],
    // Its own widget, not the AWS one. This entry used to say rules had to
    // come from the API or the CLI "until a widget exists that knows about
    // priority", and that had gone stale in a way worth recording: nothing
    // here needs to know about priority, because az/nsg._priorities_for
    // decides it from the order of this list. What actually made the AWS
    // widget unusable is smaller and sharper - an Azure rule carries a name,
    // a direction, and an access that can be Deny, and a security group rule
    // carries none of those because every rule in one is an allow. A form
    // submitting Azure rules in the AWS shape would have sent every rule as
    // Allow and built a different firewall from the one on screen.
    ["rules", "azure-rules",
     "in order — the first rule that matches a packet decides"],
  ],
  "azure-vnet": [
    ["name", "text", "a name for this network"],
    ["resource_group", "text", "Azure needs one; it is created if it is new"],
    ["location", "text", "eastus, westeurope, uksouth…"],
  ],
  "azure-vm": [
    ["name", "text", "a name for this machine"],
    ["resource_group", "text", "Azure needs one; it is created if it is new"],
    ["location", "text", "eastus, westeurope, uksouth…"],
    ["vm_size", "menu", "size — the tool refuses anything larger"],
    ["public_key", "textarea", "ssh-ed25519 AAAA… — the PUBLIC half only",
     "The same bargain the AWS key pair form makes. A password would log in, " +
     "so this never accepts one; a public key is not a secret and is all " +
     "Azure needs. Generate one below, or with ssh-keygen."],
    ["open_ports", "multi", "which ports it should answer on"],
    ["allowed_source", "menu", "where those ports may be reached from"],
    ["assign_public_ip", "checkbox", false],
  ],
};

async function buildCreateForm() {
  const known = currentType();
  const box = $("create-body");
  box.replaceChildren();

  // The panel says which type it would build without being opened, so a
  // folded one is still legible.
  $("create-sub").textContent = known.short_label || known.label;
  $("create-hint").textContent = known.read_only ? "nothing to create" : "";

  // Nothing to keep watching once the form is gone, and leaving the previous
  // type's fields here would have the live check reading boxes that are no
  // longer on the page.
  state.createInputs = null;

  if (known.read_only) {
    box.append(text("p",
      `${known.label} is audited by this tool, not created by it. There is ` +
      `nothing here it would be safe to make on your behalf.`, "muted"));
    return;
  }

  box.append(text("p", "Loading choices…", "muted"));

  // Asked once per form. Several of these are live account lookups.
  try {
    const body = await api(`/resources/${state.type}/options`);
    state.options = body.options || {};
  } catch {
    state.options = {};
  }
  if (state.type !== known.key) return;   // switched types while loading

  box.replaceChildren();

  const fields = FIELDS[state.type] || [["name", "text", ""]];
  const inputs = {};

  for (const [name, kind, hint, note] of fields) {
    const wrap = document.createElement("div");
    wrap.className = "field";
    const caption = text("label", LABELS[name] || name.replace(/_/g, " "));
    wrap.append(caption);

    if (kind === "rules" || kind === "azure-rules") {
      const makeRow = kind === "azure-rules" ? azureRuleRow : ruleRow;
      const rules = document.createElement("div");
      const add = document.createElement("button");
      add.type = "button";
      add.textContent = "add rule";
      add.onclick = () => {
        rules.append(makeRow());
        if (kind === "azure-rules") refreshPrecedence(rules);
      };
      wrap.append(add);
      box.append(wrap, rules);

      // The hint was being dropped for this field. Every other kind uses it
      // as a placeholder inside its own input, and a list of rows has no such
      // box - so "in order — the first rule that matches a packet decides"
      // was written down, never rendered, and the arrows that act on it had
      // to be guessed at. Somebody did guess, and asked what they were.
      if (kind === "azure-rules" && hint) {
        box.append(text("p", hint, "note"));
      }

      rules.append(makeRow());
      if (kind === "azure-rules") refreshPrecedence(rules);
      inputs[name] = { kind, el: rules };
      continue;
    }

    let el;
    if (kind === "checkbox") {
      el = document.createElement("input");
      el.type = "checkbox";
      el.checked = Boolean(hint);
    } else if (kind === "textarea") {
      el = document.createElement("textarea");
      el.rows = 3;
      el.placeholder = hint;
    } else if (kind === "menu") {
      const choices = state.options[name] || [];
      el = choice(choices);
      if (!choices.length) {
        wrap.append(text("span", "(nothing here yet — use Other…)", "muted"));
      }
    } else if (kind === "multi") {
      const choices = state.options[name] || [];
      el = choices.length ? multiChoice(choices)
                          : Object.assign(document.createElement("input"),
                                          { size: 32, placeholder: hint });
    } else {
      el = document.createElement("input");
      el.size = 32;
      el.placeholder = hint;
    }

    wrap.append(el);

    // Only where the control cannot say it itself. A text box already shows
    // the hint as its placeholder, and repeating it underneath printed every
    // caption twice - "name / a name for this alarm / a name for this alarm".
    let hintEl = null;
    if (hint && (kind === "menu" || kind === "multi")) {
      hintEl = text("span", hint, "hint");
      wrap.append(hintEl);
    }
    box.append(wrap);

    // A field whose contents are not self-explanatory says so underneath,
    // rather than leaving the reader to work out what they are looking at.
    if (note) box.append(text("p", note, "note"));

    inputs[name] = { kind, el, hint: hintEl };
  }

  if (state.type === "key-pair") box.append(keygenControls(inputs));

  // Above the buttons on purpose: the consequences of what has been typed are
  // read on the way to pressing Create, not after it.
  const live = document.createElement("div");
  live.id = "create-live";
  live.className = "live";
  box.append(live);

  state.createInputs = inputs;

  const row = document.createElement("div");
  row.className = "row";

  // Runs the same check the panel above already runs, into the same panel,
  // rather than a second copy of the answer below the buttons. It used to
  // write its own: pressing it printed the identical findings twice on one
  // screen, and worse, that second copy was never cleared - so editing the
  // form left a stale verdict sitting underneath the live one. A form with
  // two critical findings showed "0 critical" from an earlier press, lower
  // down the page, where it reads as the conclusion.
  const check = document.createElement("button");
  check.textContent = "Check first (creates nothing)";
  check.onclick = () => runLiveCheck(true);

  // The one that builds something is the one that looks like it does. Both
  // were the same white outlined button, so the pair read as two equal
  // options and the destructive-by-omission half of that pair is Create.
  const make = document.createElement("button");
  make.className = "primary";
  make.textContent = "Create";
  make.onclick = () => submitSpec(inputs);

  row.append(check, make);
  box.append(row);

  const out = document.createElement("div");
  out.id = "create-out";
  box.append(out);
}

/* One inbound rule, asked as three questions with names on them.

   The previous version was four bare boxes captioned "tcp", "from", "to" and
   "0.0.0.0/0", which is the tool asking the user to already know the answer.
   Port is one menu rather than a from/to pair because a range is the rare
   case and a single well-known port is the common one; "Range…" still gets
   you the pair. */
function ruleRow() {
  const row = document.createElement("div");
  row.className = "rule";

  const protocol = choice(state.options.protocol || [],
                          { allowOther: false, blank: null });
  protocol.set("tcp");

  const ports = (state.options.port || []).slice();
  const port = choice(ports, { blank: "— port —", other: "Other port or range…" });

  const range = document.createElement("span");
  range.className = "hidden";
  const from = Object.assign(document.createElement("input"), { size: 5, placeholder: "from" });
  const to = Object.assign(document.createElement("input"), { size: 5, placeholder: "to" });
  range.append(text("span", " "), from, text("span", "–"), to);

  // "Other…" on a port means either one number or a span of them, so reveal
  // the pair rather than a single box that quietly means "from".
  port.querySelector("select").addEventListener("change", (e) => {
    range.classList.toggle("hidden", e.target.value !== "__other__");
    port.querySelector("input").classList.add("hidden");
  });

  const source = choice(state.options.source || [], { blank: "— who can reach it —",
                                                      other: "Other address…" });

  const rm = document.createElement("button");
  rm.type = "button";
  rm.textContent = "remove";
  rm.onclick = () => row.remove();

  row.append(
    labelled("protocol", protocol),
    labelled("port", port, range),
    labelled("source", source),
    rm,
  );

  row.value = () => {
    const chosen = port.querySelector("select").value;
    let fromPort = null, toPort = null;
    if (chosen === "__other__") {
      fromPort = from.value.trim() ? Number(from.value) : null;
      toPort = to.value.trim() ? Number(to.value) : fromPort;
    } else if (chosen) {
      fromPort = toPort = Number(chosen);
    }
    return {
      protocol: protocol.value() || "tcp",
      from_port: fromPort,
      to_port: toPort,
      source: source.value(),
    };
  };

  return row;
}

/* Keeps the reorder controls honest about what they can do.

   With one rule there is no precedence to arrange, so the whole control is
   hidden rather than shown doing nothing - a pair of arrows that never move
   anything is what made somebody ask what they were for. With several, the
   first row cannot go up and the last cannot go down, and those two are
   disabled rather than silently ignoring the click.

   Called after every add, remove and move, because all three change which
   answers are true. */
function refreshPrecedence(list) {
  if (!list) return;
  const rows = [...list.children];

  for (const [at, row] of rows.entries()) {
    const order = row.querySelector(".rule-actions .labelled");
    if (order) order.classList.toggle("hidden", rows.length < 2);

    const [up, down] = row.querySelectorAll(".rule-actions button.move");
    if (up) up.disabled = at === 0;
    if (down) down.disabled = at === rows.length - 1;
  }
}

/* One row of an Azure firewall rule.

   Separate from ruleRow() rather than a flag on it, because the two are not
   the same shape and pretending otherwise is how a form drifts from the rules
   that judge it. An AWS rule is protocol, ports and a source, and every rule
   in a security group is an allow. An Azure rule additionally has a name, a
   direction, and an access - and access can be Deny, which is what closes a
   port that a rule below would open.

   No priority field, deliberately. az/nsg._priorities_for assigns one per
   rule from the order of this list, ten apart so a rule can be inserted in
   front later. Offering the number would let somebody submit two rules with
   the same one, which Azure rejects, or an order whose effect is not the
   order the list reads as, which Azure accepts and nobody notices. The
   arrows below move a row, and moving a row is what changes precedence. */
function azureRuleRow(index) {
  const row = document.createElement("div");
  row.className = "rule";

  const name = Object.assign(document.createElement("input"),
                             { size: 16, placeholder: "allow-ssh" });

  const direction = choice(state.options.rule_direction || [],
                           { allowOther: false, blank: null });
  direction.set("Inbound");

  const access = choice(state.options.rule_access || [],
                        { allowOther: false, blank: null });
  access.set("Allow");

  const protocol = choice(state.options.rule_protocol || [],
                          { allowOther: false, blank: null });
  protocol.set("Tcp");

  const port = choice(state.options.rule_port || [],
                      { blank: "— port —", other: "Other port or range…" });
  const source = choice(state.options.rule_source || [],
                        { blank: "— who can reach it —", other: "Other address…" });

  // Precedence is the list order, so it has to be changeable without
  // retyping the row. Buttons rather than drag: this page has no drag
  // anywhere else, and a control that only works with a mouse is worse than
  // one that works with a keyboard too.
  //
  // Captioned, because two bare arrows in a form full of firewall settings do
  // not say what they move or why it matters - somebody looking at this asked
  // what they were, which is the whole answer to whether a title attribute is
  // enough. It is not: it needs a hover to appear and never appears at all on
  // a touch screen.
  const up = document.createElement("button");
  up.type = "button";
  up.className = "move";
  up.textContent = "↑";
  up.title = "Move earlier — this rule is checked before the one above it";
  up.onclick = () => {
    const prev = row.previousElementSibling;
    if (prev) row.parentNode.insertBefore(row, prev);
    refreshPrecedence(row.parentNode);
  };

  const down = document.createElement("button");
  down.type = "button";
  down.className = "move";
  down.textContent = "↓";
  down.title = "Move later — this rule is checked after the one below it";
  down.onclick = () => {
    const next = row.nextElementSibling;
    if (next) row.parentNode.insertBefore(next, row);
    refreshPrecedence(row.parentNode);
  };

  const rm = document.createElement("button");
  rm.type = "button";
  rm.textContent = "remove";
  rm.onclick = () => {
    const list = row.parentNode;
    row.remove();
    refreshPrecedence(list);
  };

  // One grid cell, not three. The row's grid has four columns and the AWS
  // row puts six things in it; appending nine made these wrap onto their own
  // line and stretch to a column's full width, so the up arrow rendered as a
  // large empty box with a tick in the middle of it.
  const actions = document.createElement("div");
  actions.className = "rule-actions";
  actions.append(labelled("order", up, down), rm);

  row.append(
    labelled("name", name),
    labelled("direction", direction),
    labelled("allow or deny", access),
    labelled("protocol", protocol),
    labelled("port", port),
    labelled("source", source),
    actions,
  );

  row.value = () => {
    const chosen = port.querySelector("select").value;
    const typed = port.querySelector("input");
    const ports = chosen === "__other__" ? (typed.value.trim() || null)
                                         : (chosen || null);
    return {
      name: name.value.trim(),
      direction: direction.value() || "Inbound",
      access: access.value() || "Allow",
      protocol: protocol.value() || "Tcp",
      // Azure takes a single port or a range as one string ("22", "80-443"),
      // which is why this is not the from/to pair the AWS row produces.
      destination_port_range: ports,
      // The API's own field name, from models.AzureSecurityRule. Called
      // `source` here first, which the stub in app.test.mjs accepted and the
      // real route silently dropped - the group was built with no rules at
      // all and reported success. A stub written to match the page cannot
      // disagree with it; only Azure could, and did.
      source_address_prefix: source.value(),
    };
  };

  return row;
}

/* Generating a key pair without leaving the page.

   The private half goes straight from WebCrypto into a download and is never
   held anywhere this page can be asked for it again. The public half is put
   in the form field, which is the only part the API ever receives. */
function keygenControls(inputs) {
  const box = document.createElement("div");
  box.className = "keygen";

  const make = document.createElement("button");
  make.type = "button";
  make.textContent = "Generate a key pair in this browser";

  const out = document.createElement("div");

  make.onclick = async () => {
    const name = (inputs.name.el.value || "").trim() || "scp-key";
    make.disabled = true;
    out.replaceChildren(text("p", "Generating…", "muted"));

    try {
      // The same comment ssh-keygen is given by key_pairs.generate_locally,
      // so a key made here and one made from the command line are labelled
      // identically in a server's authorized_keys.
      const pair = await KeyGen.generate(`${name} (secure-cloud-provisioner)`);
      inputs.public_key.el.value = pair.publicKey;

      const filename = `${name}-${pair.filename}`;
      download(filename, pair.privateKey);

      out.replaceChildren();
      out.append(text("p",
        `${pair.type} key pair generated. The public half is in the box ` +
        `above and will be sent when you press Create.`));
      out.append(text("p",
        `The private half was downloaded as ${filename}. That is the only ` +
        `copy — it was never sent anywhere, and this page cannot produce it ` +
        `again. Move it somewhere safe and run: chmod 600 ${filename}`,
        "warn"));
      if (pair.note) out.append(text("p", pair.note, "muted"));
    } catch (e) {
      out.replaceChildren(text("p",
        `Could not generate a key here (${e.message}). Run ` +
        `ssh-keygen -t ed25519 yourself and paste the contents of the .pub ` +
        `file above.`, "bad"));
    }
    make.disabled = false;
  };

  box.append(make, out);
  return box;
}

function download(filename, content) {
  const url = URL.createObjectURL(
    new Blob([content], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function labelled(caption, ...controls) {
  const wrap = document.createElement("span");
  wrap.className = "labelled";
  wrap.append(text("small", caption));
  const line = document.createElement("span");
  line.append(...controls);
  wrap.append(line);
  return wrap;
}

function collectSpec(inputs) {
  const spec = {};
  for (const [name, { kind, el }] of Object.entries(inputs)) {
    if (kind === "checkbox") { spec[name] = el.checked; continue; }

    if (kind === "rules" || kind === "azure-rules") {
      const rules = [];
      for (const row of el.children) {
        const rule = row.value();
        // A rule with nobody it applies to is an empty row, not a rule. The
        // two clouds spell that field differently, which is the whole reason
        // they are separate models.
        if (!(kind === "azure-rules" ? rule.source_address_prefix
                                     : rule.source)) continue;
        // An Azure rule additionally needs a name and a port. A row missing
        // either is half-typed rather than a rule somebody meant, and sending
        // it produces a refusal about a field they can see is empty.
        if (kind === "azure-rules" &&
            (!rule.name || !rule.destination_port_range)) continue;
        rules.push(rule);
      }
      // Order is precedence: az/nsg assigns priorities from this sequence, so
      // the array is submitted exactly as the rows sit on screen.
      //
      // azure_rules, not rules. api/models.py keeps two lists on purpose -
      // an Azure rule names a direction and an access and writes ports as a
      // string, and forcing one model to carry both would leave half the
      // fields null whichever cloud was in use. The adapter reads
      // spec["azure_rules"] and ignores the AWS one.
      if (rules.length) {
        spec[kind === "azure-rules" ? "azure_rules" : "rules"] = rules;
      }
      continue;
    }

    if (kind === "multi") {
      const chosen = typeof el.value === "function"
        ? el.value()
        : el.value.split(",").map((s) => s.trim()).filter(Boolean);
      if (chosen.length) spec[name] = chosen;
      continue;
    }

    // menu widgets expose value(); plain inputs have a value string.
    const v = typeof el.value === "function" ? el.value() : el.value.trim();
    if (v) spec[name] = v;
  }
  return spec;
}

/* Live pre-flight, on the endpoint that was built for it.

   /check makes no cloud calls - every check_spec in the registry is pure - so
   asking again on every edit costs a local round trip and nothing else. The
   route's own docstring invites exactly this. Until now the form only asked
   when somebody pressed a button, which meant an open rule or a bucket with
   its protections switched off stayed invisible until they thought to look.
   The point of the tool is that they should not have to think to look.

   The "Check first" button stays. It writes to #create-out and that output
   persists; this writes to #create-live, which is always about what the form
   says at this moment and is cleared the instant the form stops being valid. */
const LIVE_CHECK_DELAY_MS = 400;

let liveTimer = null;
let liveSeq = 0;

function scheduleLiveCheck() {
  // A refusal is about the spec that was sent. The moment the form changes it
  // is describing something else, and it sits below the live panel where a
  // stale "0 critical" reads as the final word.
  const out = $("create-out");
  if (out && out.dataset.spec) {
    out.replaceChildren();
    delete out.dataset.spec;
  }

  clearTimeout(liveTimer);
  liveTimer = setTimeout(runLiveCheck, LIVE_CHECK_DELAY_MS);
}

async function runLiveCheck(explicit = false) {
  const box = $("create-live");
  const inputs = state.createInputs;
  if (!box || !inputs) return;

  clearTimeout(liveTimer);
  const spec = collectSpec(inputs);

  // Not an error worth showing, unless it was asked for. Somebody who has
  // typed two characters of a name is mid-thought, and a red box telling them
  // the name is missing is the tool nagging rather than helping - but somebody
  // who pressed the button and got nothing back is owed the reason.
  if (!spec.name) {
    box.replaceChildren();
    if (explicit) box.append(text("p", "A name is required.", "bad"));
    return;
  }

  if (explicit) box.replaceChildren(text("p", "Checking…", "muted"));

  // Two guards against showing an answer to a question nobody asked any more.
  // Responses can arrive out of order, so a slower earlier one must not
  // overwrite a faster later one; and the type can be switched while a request
  // is in flight, which would render one resource's findings under another's
  // form.
  const seq = ++liveSeq;
  const askedAbout = state.type;

  let body;
  try {
    body = await api(`/resources/${state.type}/check`, {
      method: "POST",
      body: JSON.stringify(spec),
    });
  } catch {
    // Quietly. Half a CIDR is a rejected request, and typing the other half
    // fixes it; a banner for every intermediate keystroke would train people
    // to ignore the area where the real findings appear.
    if (seq === liveSeq) box.replaceChildren();
    return;
  }

  if (seq !== liveSeq || state.type !== askedAbout) return;

  box.replaceChildren();
  const counts = body.counts || {};
  const warnings = body.warnings || [];

  if (!warnings.length) {
    box.append(text("p", "Nothing flagged so far.", "live-clean"));
    return;
  }

  box.append(text("p",
    `As it stands: ${counts.critical || 0} critical, ` +
    `${counts.warning || 0} warning, ${counts.info || 0} informational. ` +
    "Nothing has been created.", "live-head"));

  for (const w of warnings) {
    // The fix button is dropped here even where the finding carries one.
    // Fixing acts on a resource by id, and this one does not exist yet - the
    // remedy for a bad setting in a form is to change the form. The Azure
    // spec checks do return a rule_id, so without this the preview would
    // offer to repair something that was never made.
    box.append(renderFinding({ ...w, fix: null }, null));
  }
}

async function submitSpec(inputs, acceptRisk = false) {
  const out = $("create-out");
  out.replaceChildren(text("p", "Creating…", "muted"));

  const spec = collectSpec(inputs);
  if (!spec.name) {
    out.replaceChildren(text("p", "A name is required.", "bad"));
    return;
  }

  const path = `/resources/${state.type}`
    + (acceptRisk ? "?accept_risk=true" : "");

  let body;
  try {
    body = await api(path, { method: "POST", body: JSON.stringify(spec) });
  } catch (e) {
    // The server refuses a create whose pre-flight scan found something
    // critical. That refusal carries the findings, so it is shown the same way
    // a scan is rather than as a bare error string, and the button to proceed
    // appears only here - after the reasons have been rendered. Same bargain as
    // the cascade delete: the escape hatch exists, and it is not reachable
    // without first seeing what it costs.
    if (e.status === 400 && e.detail && e.detail.warnings) {
      out.replaceChildren(text("p", e.detail.message, "bad"));
      for (const w of e.detail.warnings) out.append(renderFinding(w, null));

      const anyway = text("button", "Create it anyway", "danger");
      anyway.onclick = () => submitSpec(inputs, true);
      out.append(anyway);

      // This refusal describes the spec as it was submitted. Editing the form
      // makes it a statement about something that is no longer on screen, so
      // it is dropped on the next change rather than left contradicting the
      // live panel above.
      out.dataset.spec = "1";
      return;
    }
    out.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  out.replaceChildren();
  delete out.dataset.spec;

  out.append(text("p", `Created ${body.resource_id}`));
  for (const p of body.problems || []) out.append(text("p", p, "muted"));
  // A new resource the last scan never saw, so that scan no longer describes
  // this type. The create response carries its own findings, which is what
  // the counts below are.
  forgetScan();
  loadList();

  const counts = body.counts;
  out.append(text("p",
    `${counts.critical} critical, ${counts.warning} warning, ${counts.info} informational`));
  for (const w of body.warnings) {
    out.append(renderFinding(w, body.resource_id));
  }
}

// ------------------------------------------------------------------ delete

// The plain delete is tried first, and the cascade is only offered once the
// server has refused it. The CLI has always had these as two separate menu
// items; collapsing them into one button that always forces would mean the
// only way to delete an empty network was the same click that terminates
// running machines.
async function startDelete(id) {
  try {
    const res = await api(`/resources/${state.type}/${encodeURIComponent(id)}`,
                          { method: "DELETE" });
    toast(res.message);
    // What this just changed is no longer what the last scan judged.
    forgetScan();
    loadList();
    resetDetail();
    return;
  } catch (e) {
    if (e.status !== 400) { toast(e.message, true); return; }
    // Refused because something is inside it. That is the case the cascade
    // dialog exists for, and the refusal itself says what is in the way.
    showCascade(id, e.message);
  }
}

// The plan is fetched before the dialog can appear, so there is no path to a
// forced delete that has not shown its inventory. The server demands the ID
// back regardless; this only makes sure a person saw the list before typing it.
async function showCascade(id, refusal, andThen) {
  const known = currentType();

  let plan;
  try {
    plan = await api(`/resources/${state.type}/${encodeURIComponent(id)}/deletion-plan`);
  } catch (e) {
    toast(e.message, true);
    return;
  }

  const body = $("modal-body");
  body.replaceChildren();
  if (refusal) body.append(text("p", `Refused: ${refusal}`, "warn"));
  body.append(text("p", plan.message));

  if (!plan.preview_available) {
    body.append(text("p",
      "This tool cannot list what that would take with it. Absence of a list " +
      "is not a promise that nothing else is destroyed.", "warn"));
  } else {
    const table = document.createElement("table");
    const head = document.createElement("tr");
    for (const h of ["Kind", "ID", "What it is", "Made by this tool"]) head.append(text("th", h));
    table.append(head);

    for (const item of plan.items) {
      const tr = document.createElement("tr");
      if (!item.created_by_this_tool) tr.className = "foreign";
      tr.append(text("td", item.kind));
      tr.append(text("td", item.id));
      tr.append(text("td", item.label));
      tr.append(text("td", item.created_by_this_tool ? "yes" : "NO"));
      table.append(tr);
    }
    body.append(table);

    if (plan.foreign_count) {
      body.append(text("p",
        `${plan.foreign_count} of these were not created by this tool. ` +
        `Something or someone else may be relying on them.`, "warn"));
    }
  }

  const typed = document.createElement("input");
  typed.size = 34;
  typed.placeholder = plan.confirm_with;

  const go = $("modal-go");
  go.disabled = true;
  typed.oninput = () => { go.disabled = typed.value.trim() !== plan.confirm_with; };

  const row = document.createElement("div");
  row.className = "row";
  row.append(text("label", `Type ${plan.confirm_with} to confirm`), typed);
  body.append(row);

  $("modal-title").textContent = `Delete this ${known.label.toLowerCase()}?`;
  go.textContent = "Delete";
  go.onclick = async () => {
    go.disabled = true;
    typed.disabled = true;

    // Progress replaces the plan. Leaving a table of ten things above a live
    // log reads as a list of what is still to come, when most of it is
    // already gone.
    const progress = deleteProgress();
    body.replaceChildren(progress.el);

    try {
      const res = await apiStream(
        `/resources/${state.type}/${encodeURIComponent(id)}` +
        `?force=true&confirm=${encodeURIComponent(plan.confirm_with)}&stream=true`,
        { method: "DELETE" },
        progress.step,
      );
      progress.finish();
      toast(res.message);
      closeModal();
      // What this just changed is no longer what the last scan judged.
      forgetScan();
      loadList();
      resetDetail();
      // The blueprint teardown continues here: the key pairs are not in the
      // network and are still there once the cascade has finished.
      if (andThen) await andThen();
    } catch (e) {
      progress.fail(e.message);
      toast(e.message, true);
      // Not re-enabled. Some of it is destroyed by now, so the plan the
      // button was built from no longer describes what is there - Cancel and
      // look again is the honest next step.
      go.textContent = "Delete";
    }
  };

  $("modal").classList.remove("hidden");
  typed.focus();
}

async function startCleanup(known) {
  const body = $("modal-body");
  body.replaceChildren(text("p", "Reading what would go…", "muted"));
  $("modal-title").textContent = "Clean up everything this tool made?";
  $("modal").classList.remove("hidden");

  // The plan carries the authorisation as well as the inventory. Nothing is
  // destroyed without this having been fetched, and a page on another site
  // cannot fetch it, because fetching means reading the response.
  let plan;
  try {
    plan = await api(`/resources/${known.key}/cleanup-plan`);
  } catch (e) {
    body.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  body.replaceChildren();
  body.append(text("p", plan.message));

  if (plan.items.length) {
    const list = document.createElement("ul");
    for (const item of plan.items) {
      list.append(text("li", `${item.id}  ${item.name || ""}`));
    }
    body.append(list);
  } else {
    body.append(text("p", "Nothing is tagged as created by this tool.", "muted"));
  }

  const typed = document.createElement("input");
  typed.size = 34;
  typed.placeholder = known.key;

  const go = $("modal-go");
  go.disabled = true;
  typed.oninput = () => { go.disabled = typed.value.trim() !== known.key; };

  const row = document.createElement("div");
  row.className = "row";
  row.append(text("label", `Type ${known.key} to confirm`), typed);
  body.append(row);

  go.textContent = "Clean up";
  go.onclick = async () => {
    go.disabled = true;
    try {
      const res = await api(
        `/resources/${state.type}/cleanup?force=true` +
        `&confirm=${encodeURIComponent(plan.confirm_with)}`,
        { method: "POST" }
      );
      const failed = res.results.filter(r => !r.ok);
      toast(`${res.results.length - failed.length} removed, ${failed.length} failed`,
            failed.length > 0);
      closeModal();
      // What this just changed is no longer what the last scan judged.
      forgetScan();
      loadList();
    } catch (e) {
      toast(e.message, true);
      go.disabled = false;
    }
  };

  typed.focus();
}

function closeModal() { $("modal").classList.add("hidden"); }

// --------------------------------------------------------------- blueprint

/* Six resources whose security is in the relationships between them rather
   than in any one of them, built in a single call.

   Both key pairs are generated here for the same reason the key-pair form
   generates one: the blueprint's own ssh-keygen path writes private halves to
   the machine running it, which over HTTP is the server. The endpoint refuses
   to build without supplied public keys, so this is not a convenience. */
function buildBlueprintPanel() {
  const box = $("blueprint-body");
  box.replaceChildren();

  box.append(text("p",
    "One network with a public and a private subnet, two firewall groups, " +
    "two key pairs, and two machines. The private machine has no public " +
    "address and its firewall trusts the bastion's group rather than any " +
    "address, so it stays reachable when the bastion's address changes and " +
    "unreachable from everywhere else."));

  const name = Object.assign(document.createElement("input"),
                             { size: 24, placeholder: "scp-bastion" });
  const nameRow = document.createElement("div");
  nameRow.className = "field";
  nameRow.append(text("label", "name"), name);

  const withInstances = Object.assign(document.createElement("input"),
                                      { type: "checkbox", checked: true });
  const instRow = document.createElement("div");
  instRow.className = "field";
  instRow.append(text("label", "launch machines"), withInstances,
                 text("span", "two t3.micro. Unticked builds everything else, free.", "hint"));

  const make = document.createElement("button");
  make.type = "button";
  make.textContent = "Generate keys and build";

  const out = document.createElement("div");

  make.onclick = async () => {
    const chosen = name.value.trim() || "scp-bastion";
    make.disabled = true;
    out.replaceChildren(text("p", "Generating two key pairs in this browser…", "muted"));

    let pairs;
    try {
      pairs = {
        "bastion-key": await KeyGen.generate(`${chosen}-bastion-key (secure-cloud-provisioner)`),
        "private-key": await KeyGen.generate(`${chosen}-private-key (secure-cloud-provisioner)`),
      };
    } catch (e) {
      out.replaceChildren(text("p",
        `Could not generate keys here (${e.message}). Use the command line ` +
        `blueprint instead: python main.py, option 6.`, "bad"));
      make.disabled = false;
      return;
    }

    // Downloaded before the build runs. If the build fails halfway the keys
    // are already registered with AWS, and a private half that never reached
    // the disk would be a key nobody can use attached to machines that exist.
    for (const [role, pair] of Object.entries(pairs)) {
      download(`${chosen}-${role}`, pair.privateKey);
    }

    out.replaceChildren();
    out.append(text("p",
      `Two private keys were downloaded as ${chosen}-bastion-key and ` +
      `${chosen}-private-key. They are the only copies and were never sent ` +
      `anywhere. Run chmod 600 on both.`, "warn"));
    out.append(text("p", "Building. This takes a minute or more…", "muted"));

    try {
      const body = await api("/blueprints/bastion", {
        method: "POST",
        body: JSON.stringify({
          name: chosen,
          region: state.region,
          with_instances: withInstances.checked,
          public_keys: {
            "bastion-key": pairs["bastion-key"].publicKey,
            "private-key": pairs["private-key"].publicKey,
          },
        }),
      });
      renderBlueprintResult(out, body);
      loadList();
    } catch (e) {
      out.append(text("p", `Build failed: ${e.message}`, "bad"));
      if (e.detail && e.detail.teardown) {
        out.append(text("h3", "What exists and how to remove it"));
        out.append(text("pre", e.detail.teardown.join("\n"), "mono-block"));
      }
    }
    make.disabled = false;
  };

  box.append(nameRow, instRow, make, out);

  const existing = document.createElement("div");
  box.append(existing);
  showExistingBlueprints(existing);
}

/* Blueprints already in the account, found on load.

   The teardown control used to live only inside the result of a build in this
   page session, which is the wrong lifetime for it entirely: reload the page
   and the only way to remove six resources was to go and do it by hand. What
   somebody wants to tear down is almost always something they built earlier.

   Found by naming rather than by a tag, because the pieces carry the same
   ManagedBy tag as everything else this tool makes and nothing records that
   they were built together. build() names them all after the blueprint, so
   the pair of keys is the signature: <name>-bastion-key and
   <name>-private-key exist together only because a blueprint made them. */
async function showExistingBlueprints(box) {
  box.replaceChildren();

  let keys, networks;
  try {
    [keys, networks] = await Promise.all([
      api("/resources/key-pair?only_ours=false"),
      api("/resources/network?only_ours=false"),
    ]);
  } catch {
    return;
  }

  const names = new Set(keys.resources.map((k) => k.id));
  const found = [];

  for (const key of keys.resources) {
    if (!key.id.endsWith("-bastion-key")) continue;
    const name = key.id.slice(0, -"-bastion-key".length);
    if (!names.has(`${name}-private-key`)) continue;

    const network = networks.resources.find((n) => n.name === name);
    found.push({
      name,
      vpc: network ? network.id : null,
      "bastion-key": key.id,
      "private-key": `${name}-private-key`,
    });
  }

  if (!found.length) return;

  box.append(text("h3", "Blueprints already in this account"));
  for (const created of found) {
    const row = document.createElement("div");
    row.className = "existing";
    row.append(text("strong", created.name));
    row.append(text("span",
      created.vpc
        ? `network ${created.vpc}, two key pairs`
        : "key pairs only — the network is already gone",
      "hint"));
    row.append(teardownControls(created));
    box.append(row);
  }
}

function renderBlueprintResult(out, body) {
  out.append(text("h3", body.ok ? "Built" : "Did not finish"));

  if (body.log.length) {
    out.append(text("pre", body.log.join("\n"), "mono-block"));
  }
  for (const p of body.problems) out.append(text("p", p, "muted"));

  if (body.instructions.length) {
    out.append(text("h3", "How to connect"));

    // The script first, because it is the answer for most people and the six
    // commands below it are the explanation. A browser cannot move a file,
    // change its mode, reach an ssh-agent or open a shell - so the nearest
    // the tool gets to doing this for you is handing over something that
    // does. It carries no key material; see blueprints/bastion.connect_script.
    if (body.script && body.script_name) {
      const row = document.createElement("div");
      row.className = "row";

      const get = document.createElement("button");
      get.textContent = "Download connect script";
      get.onclick = () => {
        download(body.script_name, body.script);
        toast(`Downloaded ${body.script_name}. Run: bash ~/Downloads/${body.script_name}`);
      };

      row.append(get, text("span",
        `or run the six commands below by hand`, "muted"));
      out.append(row);
      out.append(text("p",
        `It files both keys, makes them readable only by you, and opens a ` +
        `shell on the private machine through the bastion. It holds no key ` +
        `material — read it before running it.`, "muted"));
    }

    out.append(commandBlock(body.instructions));
  }
  if (body.teardown.length) {
    out.append(text("h3", "How to remove it"));
    out.append(commandBlock(body.teardown));
    out.append(teardownControls(body.created));
  }
}

/* Removing a blueprint is two deletes, because its pieces are not all in one
   place: a network cascade takes the machines, subnets, route tables, gateway
   and firewall groups, and the two key pairs are account-level and survive it
   untouched.

   The network half goes through the same cascade dialog the delete button in
   the listing uses - plan fetched, inventory shown, VPC ID typed back. A
   dedicated "remove blueprint" button that skipped that would be the one
   destructive path in the tool without a preview, and it destroys two running
   machines. */
/* A live log of a delete, plus a clock.

   The clock is not decoration. Nearly all of a cascade is one wait for AWS to
   detach network interfaces, and during it the server has genuinely nothing
   new to say for thirty seconds at a time - so a log alone still goes quiet,
   and quiet is the thing that reads as broken. Something moving every second
   is the difference between "this is slow" and "this has died".

   The last line stays highlighted rather than the list scrolling away,
   because what is happening now is the question being asked. */
function deleteProgress() {
  const el = document.createElement("div");
  el.className = "delete-progress";

  const heading = text("p", "Deleting. This can take several minutes.");
  const clock = text("span", "0:00", "muted mono");
  const spent = document.createElement("p");
  spent.className = "muted";
  spent.append(document.createTextNode("Elapsed "), clock);

  const log = document.createElement("ul");
  log.className = "steps";

  el.append(heading, spent, log);

  const started = Date.now();
  const tick = setInterval(() => {
    const s = Math.floor((Date.now() - started) / 1000);
    clock.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  }, 1000);

  let current = null;

  return {
    el,
    step(line) {
      if (current) current.className = "done";
      current = text("li", line, "current");
      log.append(current);
    },
    finish() {
      clearInterval(tick);
      if (current) current.className = "done";
      heading.textContent = "Done.";
    },
    fail(why) {
      clearInterval(tick);
      if (current) current.className = "failed";
      heading.textContent = "Stopped.";
      // What already happened stays on screen. Nothing rolls back here, so
      // the steps above this line are things that really were destroyed.
      log.append(text("li", why, "failed"));
    },
  };
}

function teardownControls(created) {
  const box = document.createElement("div");
  box.className = "row";

  const vpc = created.vpc;
  const keys = ["bastion-key", "private-key"]
    .map((role) => created[role])
    .filter(Boolean);

  const out = document.createElement("div");

  const go = document.createElement("button");
  go.type = "button";
  go.className = "danger";
  go.textContent = "Remove this blueprint";
  go.onclick = () => {
    if (!vpc) { removeBlueprintKeys(keys, out); return; }
    out.replaceChildren();

    // Reuse the guarded flow. Switching the page to the network type first
    // means the dialog builds its URLs against the right resource type, and
    // leaves the user looking at the list the deletion came from.
    selectType("network");
    showCascade(vpc, "", async () => {
      out.replaceChildren(text("p", `Removed ${vpc}.`));
      await removeBlueprintKeys(keys, out);
    });
  };

  box.append(go, text("span",
    keys.length
      ? `Deletes ${vpc || "the network"} after showing you what goes with it, ` +
        `then ${keys.join(" and ")}.`
      : `Deletes ${vpc} after showing you what goes with it.`,
    "hint"));

  const wrap = document.createElement("div");
  wrap.append(box, out);
  return wrap;
}

async function removeBlueprintKeys(keys, out) {
  for (const name of keys) {
    try {
      const res = await api(`/resources/key-pair/${encodeURIComponent(name)}`,
                            { method: "DELETE" });
      out.append(text("p", `${name}: ${res.message}`));
    } catch (e) {
      out.append(text("p", `${name}: ${e.message}`, "bad"));
    }
  }
  out.append(text("p",
    "The private key files are still in your downloads. This tool never had " +
    "them and cannot remove them.", "warn"));
  loadList();
  // The blueprint just stopped existing, so the list of them is now stale.
  buildBlueprintPanel();
}

// -------------------------------------------------------------------- boot

// Attached once to the container rather than to each field, so it catches rule
// rows added later and cannot accumulate a second listener every time the form
// is rebuilt. Which fields exist is read from state at the time it fires.
for (const event of ["input", "change"]) {
  $("create-body").addEventListener(event, scheduleLiveCheck);
}

$("modal-cancel").onclick = closeModal;
$("refresh").onclick = loadList;

$("cloud-toggle").onclick = () =>
  setCloud(state.cloud === "aws" ? "azure" : "aws");

for (const b of $("tabs").children) {
  b.onclick = () => selectTab(b.dataset.tab);
}
$("scan-all").onclick = scanEverything;
$("dash-refresh").onclick = loadDashboard;

// The create panel folds. Its state is remembered across type changes,
// because somebody who closed it did so to see the findings above it and
// clicking a second resource is not a request to open it again.
const fold = $("create-fold");
fold.onclick = () => {
  const open = fold.getAttribute("aria-expanded") !== "true";
  fold.setAttribute("aria-expanded", String(open));
  $("create-body").classList.toggle("hidden", !open);
};

checkHealth();
loadTypes().catch((e) => toast(e.message, true));
