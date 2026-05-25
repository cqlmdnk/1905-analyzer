# Architecture decisions

This document records the architectural decisions made during the initial
setup of ieee1905-suite, along with the reasoning behind each one. If a
decision is revised, a new section is appended; the original is **not
removed**, so history stays traceable.

---

## ADR-001: Web UI (FastAPI + Vue 3 / PrimeVue)

**Decision:** The UI is built as a FastAPI (Python) backend +
Vue 3 + TypeScript + PrimeVue (in-browser) frontend. The backend runs
privileged (root / admin for raw sockets); the frontend runs in the
user's normal browser and connects over localhost with a token.

**Alternatives considered:**
- PyQt6 / PySide6 (native desktop) — stronger single-machine UX, but
  remote agent / headless scenarios would require an extra layer.
- Textual (TUI) — lightweight, but inadequate visual surface for a
  hex view, packet tree, and intercept UX.

**Consequences:**
- In headless mode the backend runs on its own (CI conformance runner).
- Remote-agent scenarios are natural: backend on one host, browser on
  another.
- The frontend is built independently and served as static assets by
  the backend; `pipx install` ships a single artifact.

---

## ADR-002: Spec scope — 1905.1 + EasyMesh R1–R4 (full)

**Decision:** Support IEEE 1905.1-2013 (the base standard, amendments
included) and Wi-Fi Alliance EasyMesh R1, R2, R3, R4 in full. R5 will
be evaluated when it ships (currently out of scope).

**Consequences:**
- ~150+ TLVs to implement.
- Profile-2 TLV length format (32-bit), introduced in R2, is supported
  from the start.
- TLV implementations land in waves (Phase 1: 1905.1; Phase 2: EM).

---

## ADR-003: Capture engine — libpcap / Npcap primary, Scapy optional

**Decision:** Primary packet I/O is built on `libpcap` (Linux / macOS)
and `Npcap` (Windows), accessed through `pcapy-ng` or
`python-libpcap`. TLV encode / decode is entirely our own code.
Scapy remains as an optional prototyping backend.

**Rationale:**
- In bridge mode, performance matters (every L2 frame transits
  user-space).
- Modification requires byte-level control; Scapy's layer abstraction
  is too coarse / opinionated for our use case.
- Wireshark-compatible PCAP / PCAPNG read / write is native to libpcap.

**Migration plan:** Phases 0–1 use Scapy's `L2Socket`
(it solves cross-platform plumbing fast). Phase 4 (bridge mode)
switches to libpcap.

**Consequences:**
- Linux: recommend `setcap cap_net_raw,cap_net_admin+eip` on the
  Python interpreter.
- macOS: BPF requires root; the ChmodBPF helper is documented.
- Windows: Npcap is a documented prerequisite.

---

## ADR-004: Two-interface bridge / MITM; transparent for all L2 traffic

**Decision:** In bridge mode the user picks two interfaces
(e.g. `eth0` / `eth1`). **All L2 traffic** is forwarded transparently
end to end; only 1905 traffic (EtherType `0x893a`) can be parsed and
modified by rules / intercept.

**Prerequisites (user side):**
- The bridged interfaces must be **IP-less** and in **promiscuous**
  mode (`ip addr flush dev ethX`, `ip link set ethX promisc on`). We
  expose a "prepare interfaces" button in the UI to automate this.
- Linux: instead of a kernel bridge, **user-space forwarding** (raw
  sockets on both interfaces).
- macOS: BPF read + write back.
- Windows: Npcap on both interfaces.

**Consequences:**
- Non-1905 traffic forwards with near-zero overhead (copy + send).
- 1905 traffic: decode → match-rules → maybe-modify → re-encode → send.
- A single-threaded bridge loop is sufficient; per-interface worker
  threads optional.

---

## ADR-005: Modification — rule-based + interactive breakpoint

**Decision:** Two first-class modification mechanisms:

1. **Rule-based (YAML)**: static, repeatable rules, CI-friendly. Hot
   reloaded from `ieee1905-suite/rules/*.yaml`.
2. **Interactive intercept (Burp-style)**: toggle in the UI; matched
   frames are forwarded to the frontend over WS, the user edits and
   decides forward / drop.

Additionally, **drop / delay / duplicate** are first-class rule actions
(useful for fault injection).

A **Python script hook** can be added later as an opt-in advanced
feature (Phase 7+).

---

## ADR-006: Two-tier TLV plugin system (YAML + Python)

**Decision:**
- **YAML declarative**: for fixed-layout TLVs. Field list (u8 / u16 /
  u32 / array / string / mac / ipv4 / ipv6 / …). Users add TLVs
  without writing code.
- **Python plugin**: for bit-level packing, conditional fields, complex
  parsing. Registered with the `@register_tlv` decorator.

Vendor-specific TLV (`0x0B`) automatically sub-dispatches on the OUI.
Unknown TLVs render as "Unknown" with a hex / ASCII view.

**Security:** Python plugins are opt-in (config flag or UI prompt) —
they execute arbitrary code.

---

## ADR-007: Single unified mode

**Decision:** No mode switcher in the UI. All capabilities (sniff /
inject / bridge / intercept / conformance) live in a single workspace;
panels open and close based on what the user is doing. Backend state
machines are independent of each other.

**Rationale:** Modal UX is friction for experienced users; we'll offer
a guided tour / walkthrough for newcomers instead.

---

## ADR-008: Privilege separation

**Decision:**
- The FastAPI backend runs as root / admin (required for raw sockets).
- The frontend runs in the user's normal browser.
- Transport is localhost-only by default, authenticated with a
  randomly generated token.
- Linux: optionally root-less via Linux capabilities
  (`setcap cap_net_raw,cap_net_admin+eip $(which python3)`).

**Rejected:** Helper daemon + RPC split — overkill at this stage. Can
be revisited if needed.

---

## ADR-009: Python 3.11+, Ubuntu 22.04 LTS primary target

**Decision:** Minimum Python is 3.11 (modern type hints, `tomllib`,
mature asyncio). Primary Linux distribution is Ubuntu 22.04+; macOS
13+ and Windows 10+ are supported.

---

## ADR-010: GPL-2.0-or-later license

**Decision:** Open source, GPLv2 or later. Every source file carries
an SPDX header: `# SPDX-License-Identifier: GPL-2.0-or-later`.

**Consequences:**
- All dependencies must be GPLv2-compatible (Scapy GPLv2, libpcap BSD,
  FastAPI MIT, Vue MIT, PrimeVue MIT — all compatible).
- The contributor guide opts for DCO over CLA.

---

## ADR-011: Primary use cases — debug + interop + research

**Decision:** The suite gives equal weight to three primary use cases:
(a) the user debugging their own device, (b) interop testing of
third-party devices, (c) research, learning, protocol observation.
Formal certification ceremony (audit trail, immutable reports) is out
of scope.

**Consequences:**
- High analyzer quality (debug + research).
- DUT emulator is important (interop testing without a real peer).
- Conformance suite emits pass / fail results but makes no certification
  claim.
- Plugin system (custom vendor TLVs) is critical for interop.
- Fuzz / drop-delay-duplicate actions are valuable for research.

## ADR-012: Independence policy

**Decision:** The suite has no dependency on any other 1905 / EasyMesh
implementation (prplMesh, vendor SDKs, hostap multi-AP). It relies
only on the standards themselves (IEEE 1905.1, the public Wi-Fi
EasyMesh spec) and on general system libraries (libpcap, Npcap).

**Important exception:** PCAP / PCAPNG format compatibility is treated
as a *standards-based feature*, not as a Wireshark integration —
sharing data with Wireshark comes for free.

**Consequences:**
- prplMesh is not used as a reference; tests run from our own
  PCAP / PCAPNG fixture set.
- No direct linkage with vendor SDKs; vendor TLVs come in as
  user-supplied plugins.
- Not bound to the Wi-Fi Alliance EasyMesh Test Plan (which is under
  NDA); tests are derived from the public spec text.
- A "Lua dissector export" (EXPLORATION.md D.1) does not violate
  independence — it is a side-product, not a dependency.

## ADR-013: DUT emulator in v0.2

**Decision:** Fake-controller and fake-agent emulators land in v0.2.
(Previously planned as a v0.3+ bonus.)

**Rationale:** The interop testing use case often lacks a real peer
device; without an emulator the suite would be incomplete for that
audience.

**Scope (v0.2):**
- Fake controller: respond to Topology Discovery, minimal
  AP-Autoconfig flow (no WSC or minimal), Topology Query / Response.
- Fake agent: minimal responses to controller-driven messages, send
  Topology Notification.
- Full WSC and DPP onboarding emulation are deferred to v0.3.

## ADR-014: Frontend — Vue 3 + PrimeVue + i18n (EN primary, TR secondary)

**Decision:** The frontend is Vue 3 + TypeScript + Vite + PrimeVue +
Pinia + vue-router. `vue-i18n` provides EN (primary) and TR
(secondary) locales.

**Consequences:**
- All UI strings live in `messages.en.json` + `messages.tr.json`.
- Backend API responses are locale-agnostic (codes, numbers, enums);
  human-readable strings are translated in the frontend.
- **All documentation, including planning docs (ROADMAP, ADRs,
  EXPLORATION), is written in English** so the project is accessible
  to external contributors.

> Note: an earlier revision of this ADR allowed Turkish planning
> documents for the convenience of the original author. That allowance
> has been withdrawn; the entire repository is English-only on disk.

## ADR-015: EasyMesh R4 — full scope

**Decision:** Every TLV and message type defined in EasyMesh R4
(Wi-Fi 7 / EHT capability, Affiliated AP / STA, MLD configuration,
security / QoS extensions) is fully supported in v0.3.

**Consequences:** R1 lands in v0.2; R2 / R3 land early in v0.3; R4
lands late in v0.3. Profile-2 (R2 onward) 32-bit TLV length is
supported from the start.

## ADR-016: UI quality bar — Wireshark-level

**Decision:** The UI is not an MVP — it aims for professional quality:
- Keyboard navigation (packet list: j / k; TLV tree: arrow keys; …)
- Bidirectional hex view ↔ TLV tree highlighting (select bytes →
  highlight node, and vice versa)
- Packet diff view (compare two packets / two captures)
- Intercept queue UI (Burp-style)
- Display filter language (a small subset of the Wireshark style:
  `ieee1905.tlv.type == 0x01`)
- Live update + scroll lock + jump-to-packet

**Consequences:**
- Frontend workload is ~3× larger than a baseline MVP UI.
- v0.1 ships a bit later but with a sturdier foundation.
- Complex components (display filter parser, hex viewer, diff) are
  covered by dedicated tests.
