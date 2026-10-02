# open-forticlient

An effort to build a minimal, open macOS client for a **FortiGate IPsec IKEv2 VPN
using SAML/SSO authentication**, motivated by a specific defect in the official
free FortiClient 7.4.3:

> **The tunnel is torn down every time the Mac screen locks.**

The official client registers for the macOS screen-lock/sleep notification and
*deliberately* disconnects the VPN (log line: `System sleep disconnect enabled`).
Because a corporate screen-lock timeout cannot be disabled, the VPN drops many
times a day and must be re-authenticated through SAML each time.

This repo documents how the official client works (reverse-engineered from the
shipping 7.4.3 binaries on this machine) and tracks the design of a replacement
that simply **does not disconnect on lock**.

## Status

Research / documentation stage. No client implemented yet. What we have:

- ✅ Root cause of the lock-disconnect confirmed from logs + binary.
- ✅ The full SAML-over-IPsec authentication handshake reverse-engineered and the
  initial HTTP step reproduced against the live gateway.
- ✅ The FortiClient IKEv2 dialect (vendor IDs, Fortinet-private notify payloads,
  EAP token flow) mapped from the `iked` daemon.
- ✅ Reusable tooling (a Mach-O/Swift disassembly annotator; a loopback SAML
  callback catcher).
- 🔜 Decide between the three implementation strategies in
  [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Layout

| Path | What |
|------|------|
| [`Issues/`](Issues/) | Backlog — one Markdown file per issue/todo (see below). |
| [`AGENTS.md`](AGENTS.md) | How to work in this repo + the `Issues/` convention. |
| [`docs/FINDINGS.md`](docs/FINDINGS.md) | Root-cause analysis, component map, log evidence. |
| [`docs/saml-ipsec-protocol.md`](docs/saml-ipsec-protocol.md) | The reverse-engineered SAML→IKEv2/EAP handshake. |
| [`docs/ike-dialect.md`](docs/ike-dialect.md) | Fortinet's IKEv2 vendor IDs, notify codes, and config attributes. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Candidate implementation strategies and open questions. |
| [`tools/annotate_macho.py`](tools/annotate_macho.py) | Annotate an x86-64 `objdump` listing of a Swift/ObjC Mach-O. |
| [`tools/saml_catch.py`](tools/saml_catch.py) | Minimal loopback HTTP server that logs the SAML redirect. |
| [`tools/README.md`](tools/README.md) | How to use the tools. |

## Issues / backlog

Work items are tracked in-repo as one Markdown file per issue under
[`Issues/`](Issues/), each with YAML front matter (`id`, `title`, `status`,
`assignee`, `created`, and optional `priority`/`labels`/`depends_on`) and a short
body. The structure and conventions are documented in [`AGENTS.md`](AGENTS.md).
The highest-value open items are **Issue 1** (is the lock-disconnect a toggleable
preference? — possible zero-code fix) and **Issue 2** (enable/test server-side
`client-resume` on the FortiGate).

## Scope and intent

This is an **interoperability / self-hosting** project for the machine's own
operator, who is the legitimate VPN user and a FortiGate administrator. It is
about reconnection behavior, not about bypassing authentication: the replacement
still performs the same SAML login and the same IKE authentication the official
client does. No credentials, tokens, or secrets are stored in this repo.

## Environment this was captured on

- macOS 26 (`Darwin 27.0.0`), Apple Silicon.
- FortiClient `7.4.3.4323` (free VPN-only build), installed at `/Applications/FortiClient.app`.
- Profile type: **IPsec IKEv2**, `EnableSSL=1`/`EnableIPSec=1`, `UseExternalBrowser=1`,
  `AuthMethod=0` (SAML/SSO), IKE SAML port `9443`.
