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

const state = { types: [], type: null, region: "us-east-1", options: {} };

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

  // The whole choice, not just its value, so a caller can read anything else
  // the API attached to it — an alarm namespace carries the unit its
  // threshold is measured in.
  wrap.selected = () => options.find((o) => o.value === select.value) || null;

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

// ------------------------------------------------------------------- types

async function loadTypes() {
  const body = await api("/resources");
  state.types = body.resources;

  const nav = $("types");
  nav.replaceChildren();
  for (const t of state.types) {
    const b = document.createElement("button");
    b.textContent = t.read_only ? `${t.label} (audit only)` : t.label;
    b.onclick = () => selectType(t.key);
    b.dataset.key = t.key;
    nav.append(b);
  }
  if (state.types.length) selectType(state.types[0].key);
}

function currentType() {
  return state.types.find((t) => t.key === state.type);
}

function selectType(key) {
  state.type = key;
  for (const b of $("types").children) {
    b.classList.toggle("active", b.dataset.key === key);
  }

  // "Only ones this tool made" is meaningless for a type it never makes, and
  // leaving it ticked on an audited type shows an empty list for something
  // the account is full of.
  const audited = state.types.find((t) => t.key === key).read_only;
  $("only-ours").checked = !audited;
  $("only-ours").disabled = audited;

  $("detail-body").replaceChildren(text("p", "Pick something from the list.", "muted"));
  buildCreateForm();
  loadList();
}

// ----------------------------------------------------------------- listing

async function loadList() {
  const known = currentType();
  $("listing-title").textContent = known.label;

  const list = $("list");
  list.replaceChildren(text("p", "Loading…", "muted"));

  const onlyOurs = $("only-ours").checked;
  const withScan = $("with-scan").checked;

  let body;
  try {
    body = await api(
      `/resources/${state.type}?only_ours=${onlyOurs}&with_scan=${withScan}`
    );
  } catch (e) {
    list.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  renderCleanup(known);

  if (!body.resources.length) {
    list.replaceChildren(text("p", "Nothing here.", "muted"));
    return;
  }

  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const h of [known.id_label, "Name", "Worst", "Findings", ""]) {
    head.append(text("th", h));
  }
  table.append(head);

  for (const r of body.resources) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.onclick = () => showDetail(r.id);

    tr.append(text("td", r.id));
    tr.append(text("td", r.name || ""));
    tr.append(text("td", r.unreachable ? "?" : (r.worst_level || "clean")));
    tr.append(text("td", r.counts
      ? `${r.counts.critical} critical, ${r.counts.warning} warning, ${r.counts.info} info`
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

  list.replaceChildren(table);
}

function renderCleanup(known) {
  const box = $("cleanup-box");
  box.replaceChildren();
  if (known.read_only) return;

  const b = document.createElement("button");
  b.textContent = `Clean up every ${known.label.toLowerCase()} this tool made`;
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
  body.append(text("h3", `${known.id_label}: ${id}`));

  const counts = data.counts;
  body.append(text("p",
    `${counts.critical} critical, ${counts.warning} warning, ${counts.info} informational`));

  body.append(text("h3", "Findings"));
  if (!data.warnings.length) {
    body.append(text("p", "Nothing found.", "muted"));
  }
  for (const w of data.warnings) {
    body.append(renderFinding(w, id));
  }

  body.append(text("h3", "What it is"));
  body.append(text("pre", JSON.stringify(data.settings, null, 2), "mono-block"));
}

function renderFinding(w, resourceId) {
  const box = document.createElement("div");
  box.className = `finding ${w.level}`;
  box.append(text("div", w.level, "level"));
  box.append(text("div", w.message));

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

  return box;
}

// ------------------------------------------------------------------ create

// Only the fields each resource actually reads. The API takes one spec model
// for every type and each adapter ignores what does not apply to it, but
// showing a bucket a field about subnets would suggest it meant something.
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
    ["namespace", "menu", "what it watches"],
    ["threshold", "text", "choose what to watch first — it decides what this number means"],
    ["email", "text", "where to send the alert",
     "AWS emails this address a confirmation link when the alarm is " +
     "created, and delivers nothing to it until somebody clicks it. An " +
     "alarm whose only address never confirmed is as silent as one with no " +
     "address at all, so the scan reports that separately once it exists."],
    ["notify", "checkbox", true],
  ],
};

async function buildCreateForm() {
  const known = currentType();
  const box = $("create-body");
  box.replaceChildren();

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
    const caption = text("label", name.replace(/_/g, " "));
    wrap.append(caption);

    if (kind === "rules") {
      const rules = document.createElement("div");
      const add = document.createElement("button");
      add.type = "button";
      add.textContent = "add rule";
      add.onclick = () => rules.append(ruleRow());
      wrap.append(add);
      box.append(wrap, rules);
      rules.append(ruleRow());
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
    let hintEl = null;
    if (hint && kind !== "checkbox" && kind !== "textarea") {
      hintEl = text("span", hint, "hint");
      wrap.append(hintEl);
    }
    box.append(wrap);

    // A field whose contents are not self-explanatory says so underneath,
    // rather than leaving the reader to work out what they are looking at.
    if (note) box.append(text("p", note, "note"));

    inputs[name] = { kind, el, hint: hintEl };
  }

  // A threshold is a bare number and means nothing without its unit: 20 is
  // twenty dollars under billing and twenty percent under CPU. The unit
  // travels on the metric, so the hint beside the box follows whatever is
  // being watched rather than being written twice in this file.
  if (inputs.namespace && inputs.threshold) {
    const explainUnit = () => {
      const chosen = inputs.namespace.el.selected
        ? inputs.namespace.el.selected() : null;
      const hint = inputs.threshold.hint;
      if (!hint) return;
      hint.textContent = chosen && chosen.unit
        ? chosen.unit
        : "choose what to watch first — it decides what this number means";
    };

    box.addEventListener("change", explainUnit);
    explainUnit();
  }

  if (state.type === "key-pair") box.append(keygenControls(inputs));

  const row = document.createElement("div");
  row.className = "row";

  const check = document.createElement("button");
  check.textContent = "Check first (creates nothing)";
  check.onclick = () => submitSpec(inputs, true);

  const make = document.createElement("button");
  make.textContent = "Create";
  make.onclick = () => submitSpec(inputs, false);

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

    if (kind === "rules") {
      const rules = [];
      for (const row of el.children) {
        const rule = row.value();
        // A rule with nobody it applies to is an empty row, not a rule.
        if (!rule.source) continue;
        rules.push(rule);
      }
      if (rules.length) spec.rules = rules;
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

async function submitSpec(inputs, dryRun, acceptRisk = false) {
  const out = $("create-out");
  out.replaceChildren(text("p", dryRun ? "Checking…" : "Creating…", "muted"));

  const spec = collectSpec(inputs);
  if (!spec.name) {
    out.replaceChildren(text("p", "A name is required.", "bad"));
    return;
  }

  const path = dryRun
    ? `/resources/${state.type}/check`
    : `/resources/${state.type}` + (acceptRisk ? "?accept_risk=true" : "");

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
      anyway.onclick = () => submitSpec(inputs, false, true);
      out.append(anyway);
      return;
    }
    out.replaceChildren(text("p", e.message, "bad"));
    return;
  }

  out.replaceChildren();

  if (!dryRun) {
    out.append(text("p", `Created ${body.resource_id}`));
    for (const p of body.problems || []) out.append(text("p", p, "muted"));
    loadList();
  } else {
    out.append(text("p", "Nothing was created. This is what it would report:"));
  }

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
    loadList();
    $("detail-body").replaceChildren(text("p", "Pick something from the list.", "muted"));
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
    try {
      const res = await api(
        `/resources/${state.type}/${encodeURIComponent(id)}` +
        `?force=true&confirm=${encodeURIComponent(plan.confirm_with)}`,
        { method: "DELETE" }
      );
      toast(res.message);
      closeModal();
      loadList();
      $("detail-body").replaceChildren(text("p", "Pick something from the list.", "muted"));
      // The blueprint teardown continues here: the key pairs are not in the
      // network and are still there once the cascade has finished.
      if (andThen) await andThen();
    } catch (e) {
      toast(e.message, true);
      go.disabled = false;
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
    out.append(text("pre", body.instructions.join("\n"), "mono-block"));
  }
  if (body.teardown.length) {
    out.append(text("h3", "How to remove it"));
    out.append(text("pre", body.teardown.join("\n"), "mono-block"));
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

const regionSelect = $("region");
for (const r of REGIONS) regionSelect.append(new Option(r, r));
regionSelect.value = state.region;

$("modal-cancel").onclick = closeModal;
$("refresh").onclick = loadList;
$("only-ours").onchange = loadList;
$("with-scan").onchange = loadList;

// Changing region changes what every menu in the create form can offer, so
// the form is rebuilt rather than left showing another region's networks.
regionSelect.onchange = (e) => {
  state.region = e.target.value;
  buildCreateForm();
  loadList();
};

checkHealth();
buildBlueprintPanel();
loadTypes().catch((e) => toast(e.message, true));
