# AGENTS.md

Guidance for anyone (human or agent) working in this repo.

## What this project is

OFTC is a standalone macOS **FortiGate IPsec IKEv2 + SAML** client. The active
app, provider, engine, and CLI are in [app/](app/) and [client/](client/).
The former Fortinet-backed controller and experiment source are preserved in
Git commit `b9ade25`, not in the active source tree. Start with
[README.md](README.md), [docs/architecture.md](docs/architecture.md), and
[docs/ROADMAP.md](docs/ROADMAP.md).

## Issue tracking: the `Issues/` directory

Work items live as one Markdown file per issue in [`Issues/`](Issues/). This keeps
the backlog in-repo, diff-able, and reviewable alongside the code. There is no
external tracker.

### File naming

```
Issues/<zero-padded-id>-<kebab-case-slug>.md
```

e.g. `Issues/001-investigate-lock-disconnect-toggle.md`. The numeric `id` in the
filename matches the `id:` in the front matter.

### File structure

YAML front matter followed by a Markdown body:

```markdown
---
id: 104                      # unique integer, matches the filename prefix
title: Fix database connection leak
status: todo                 # todo | in-progress | blocked | done | wontfix
assignee: unassigned         # a name/handle, or "unassigned"
created: 2026-10-02          # ISO date (YYYY-MM-DD)
priority: high               # optional: high | medium | low
labels: [db, bug]            # optional: list of tags
depends_on: [101, 102]       # optional: issue ids that must land first
---
### Description
The pool isn't closing properly on hot-reload.

### Tasks
- [ ] a checkbox list of concrete steps

### Acceptance
What "done" looks like.

### Refs
Links to docs/ sections, files, or external sources.
```

**Required** front-matter keys: `id`, `title`, `status`, `assignee`, `created`.
**Optional**: `priority`, `labels`, `depends_on`. The body sections beyond
`### Description` are a recommended convention, not mandatory — but keep issues
self-contained (someone should be able to act without re-reading the whole repo).

### Conventions

- **Allocate the next free `id`** when creating an issue; never reuse one.
- **Keep `status` current.** When you start, set `in-progress`; when a prerequisite
  blocks you, set `blocked` and note it (and ideally `depends_on`); when finished,
  set `done` (leave the file as a record rather than deleting it). Use `wontfix`
  with a one-line reason if abandoning.
- **Check off `### Tasks`** as you complete them, so partial progress is visible.
- If scope shifts materially, prefer a new issue with `depends_on` over silently
  expanding an existing one.

### Quick commands

```bash
# list open issues with their status
grep -L 'status: done' Issues/*.md | xargs -I{} sh -c \
  'echo "$(grep -m1 ^id: {}) | $(grep -m1 ^status: {}) | $(grep -m1 ^title: {})"'

# next free id
ls Issues/ | sed -E 's/^0*([0-9]+).*/\1/' | sort -n | tail -1
```

## Working style for this repo

- **Build from active sources.** `app/build.sh` must use `app/` inputs only.
  Use a fresh build directory; do not point a build at an installed or
  notarized app.
- **Keep evidence levels distinct.** Offline build, Developer ID signing,
  notarization, installation, extension activation, and live traffic are
  separate claims. The initial rollout gaps are in
  [docs/initial-rollout-gaps.md](docs/initial-rollout-gaps.md).
- **No secrets in the repo.** SAML `tokenid`s are single-use credentials; they and
  raw captures are covered by `.gitignore` and must never be committed. Large
  reverse-engineering dumps (`*.asm`, `strings`) are regenerable and also ignored.
  The former research tools are in Git commit `b9ade25`.
- **This is interoperability for the machine's own operator** (the legitimate VPN
  user and FortiGate admin). The replacement performs the same authentication the
  official client does; it changes reconnection behavior, not access control.
