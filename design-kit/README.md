# Design kit

Eleven self-contained previews of the page at `/ui`, for taking into a design
tool. Generated from the real page in a real browser — not hand-drawn — so what
is here is what ships.

Regenerate after any change to `style.css` or `index.html`:

```bash
cd /home/user/new/secure-cloud-provisioner/frontend && node design-kit.mjs
```

## Why these are generated rather than copied

`index.html` is a header and four empty `<section>`s. Everything else — tabs,
tables, findings, forms — is drawn by `app.js` from API responses. Opening the
file in a design tool shows an empty shell with no colour in it at all.

So the generator renders the real page against a stub API carrying realistic
findings, then lifts the rendered subtrees out and inlines `style.css`. Each
file opens on its own with no server, no network and no API.

The stub data is not invented. Warning wording, CIS citations and the
acknowledgement shape are taken from the scanners; the shapes are the ones
`api/models.py` actually returns. If a preview shows `undefined`, the stub has
drifted from the API and the generator needs updating, not the design.

## What is here

| Group | File | What it is for |
|---|---|---|
| Foundations | `foundations/severity-colour.html` | The four severity treatments side by side |
| Components | `components/header.html` | Title, cloud switch, region/location, health pill |
| Components | `components/cloud-switch.html` | The switch alone, both positions |
| Components | `components/type-tabs.html` | One cloud's resource tabs, with audit-only tags |
| Components | `components/finding.html` | Finding cards: four severities, fix button, citation |
| Components | `components/resource-table.html` | The listing, including a foreign-resource row |
| Components | `components/create-form.html` | Captioned rows, menus, the rule builder |
| Components | `components/caution-banner.html` | The per-cloud warning |
| Components | `components/blueprint.html` | The bastion panel (AWS only) |
| Pages | `pages/aws.html` | The whole AWS page |
| Pages | `pages/azure.html` | The whole Azure page |

Each file's first line is a `<!-- @dsCard group="…" -->` marker, which is what
the Design System pane indexes by. `cards.json` lists them with names and
subtitles.

The two `pages/` files have their scripts stripped, so they are **static** —
the switch and the tabs will not respond. They are for looking at.

## Two constraints that are not taste

**Colour means severity, and nothing else.** It is written into the top of
`style.css`, it is why the cloud switch is monochrome, and it is what makes red
read as red. A brand palette here is a real proposal, but it has to be argued
with rather than quietly applied — the page has exactly three colours that
carry meaning and every one of them is about risk.

**Prose is prose and identifiers are identifiers.** Findings are aimed at
somebody who does not know the jargon, so they are set in a sans face.
Anything compared character by character — resource IDs, keys, commands, the
CIS citation — stays monospace, because that is where a lost character
matters.

## What must survive a redesign

`app.js` finds these by name. Restyle them freely; renaming or removing one
breaks the page, and the test suite will not catch all of it, because jsdom
computes no styles.

**IDs** — `cloud`, `types`, `place`, `place-label`, `caution`, `blueprint`,
`blueprint-body`, `list`, `listing-title`, `detail-body`, `create-body`,
`create-live`, `create-out`, `cleanup-box`, `modal`, `modal-title`,
`modal-body`, `modal-go`, `modal-cancel`, `toast`, `health`, `only-ours`,
`only-ours-label`, `with-scan`, `refresh`

**Classes the JavaScript applies** — `active`, `hidden`, `field`, `rule`,
`labelled`, `finding` with `critical` / `warning` / `info`, `acknowledged`,
`clickable`, `danger`, `pill ok` / `pill bad`, `existing`, `foreign`, `keygen`,
`live`

The switch also reads two CSS custom properties, `--positions` and
`--position`, which is how the knob slides across however many clouds are
registered. It must not assume two.
