# ieee1905-suite — Roadmap

Cross-platform (Linux/macOS/Windows) IEEE 1905.1 + Wi-Fi EasyMesh
analyzer, injector, live modifier, and conformance test suite.

License: **GPL-2.0-or-later**
Primary platform: Ubuntu 22.04+ LTS (cross-platform CI: macOS + Windows)

---

## Goals (summary)

1. **Passive analyzer** — live capture from an interface or read from
   PCAP/PCAPNG, parse every 1905.1 + EasyMesh R1–R4 CMDU/TLV, present a
   Wireshark-style 3-pane view.
2. **Active injector** — single packet / template / scriptable scenario.
3. **Live bridge / MITM** — transparently bridge **all L2 traffic** between
   two interfaces, end to end; analyze and modify only 1905 traffic.
4. **Modification engine** — (a) YAML / JSON rule-based, (b) Burp-style
   interactive breakpoint, (c) drop / delay / duplicate actions.
5. **Conformance test suite** — both interactive (web UI) and
   CI / headless (`pytest` + JUnit / HTML report); tests mapped to spec
   sections.
6. **Extensible TLV registry** — users add their own TLV / vendor extension
   schemas as YAML or as Python plugins; unknown types are shown as hex +
   ASCII labelled "Unknown".
7. **Web UI** — FastAPI backend (privileged) + Vue 3 / PrimeVue frontend
   (in-browser, localhost + token auth).

---

## Phase 0 — Foundations

- [x] `pyproject.toml`, GPLv2 LICENSE, `src/ieee1905/` layout
- [x] Cross-platform packet I/O abstraction (`io/backend.py`):
  - Linux: AF_PACKET raw socket
  - macOS: `/dev/bpf*` (Scapy backend initially)
  - Windows: Npcap (loader script verifies presence)
  - Universal fallback: Scapy (`L2Socket`)
- [x] Config dirs: `~/.config/ieee1905-suite/` (Linux / mac),
      `%APPDATA%` (Windows)
- [x] Logging (configurable, JSON output supported)
- [x] GitHub Actions: lint (ruff) + type-check (mypy) + tests (pytest)
      across Linux / macOS / Windows
- [x] Pre-commit hooks (ruff, ruff-format, mypy, basic file hygiene)
- [x] Privilege strategy:
  - Linux: `setcap cap_net_raw,cap_net_admin+eip` recommended;
    `sudo` works too
  - macOS: root for BPF, or Wireshark's ChmodBPF helper
  - Windows: Administrator terminal
  - Backend runs privileged; browser frontend talks to it via
    localhost + token

## Phase 1 — Core CMDU / TLV codec ✓ done

- [x] CMDU header: message version (`0x00`), reserved, message type
      (uint16), MID (uint16), fragment ID, last-fragment + relayed flags
- [x] Fragmentation / reassembly (keyed on MID + fragment ID), stale-group
      eviction, single-fragment fast path
- [x] TLV base + registry plumbing; ``RawTLV.parse_one`` iterator and
      ``decode_raw`` dispatch with Unknown-TLV fall-through
- [x] ``CMDU.typed_tlvs()`` convenience iterator (Raw → Typed)
- [x] Cross-platform Ethernet II frame helper (with 802.1Q strip) so the
      capture side feeds CMDU bytes cleanly
- [x] IEEE 1905.1 baseline TLVs (`0x00`–`0x1E`, 30 types):
  - `0x00` End of message
  - `0x01` AL MAC address
  - `0x02` MAC address
  - `0x03` Device information
  - `0x04` Device bridging capability
  - `0x06` Non-1905 neighbor device list
  - `0x07` 1905 Neighbor device
  - `0x08` Link metric query
  - `0x09` Transmitter link metric
  - `0x0A` Receiver link metric
  - `0x0B` Vendor specific
  - `0x0C` Link metric result code
  - `0x0D` SearchedRole
  - `0x0E` AutoconfigFreqBand
  - `0x0F` SupportedRole
  - `0x10` SupportedFreqBand
  - `0x11` WSC frame
  - `0x12` Push button event notification
  - `0x13` Push button join notification
  - `0x14` Generic PHY device information
  - `0x15` Device identification
  - `0x16` Control URL
  - `0x17` IPv4
  - `0x18` IPv6
  - `0x19` Generic PHY event notification
  - `0x1A` 1905 profile version
  - `0x1B` Power off interface
  - `0x1C` Interface power change information
  - `0x1D` Interface power change status
  - `0x1E` L2 neighbor device
- [x] Message types enum (18 1905.1 messages: Topology Discovery /
      Notification / Query / Response, Link metric Query / Response,
      AP-Autoconfig Search / Response / WSC / Renew, push-button event /
      join, higher-layer query / response, generic-PHY query / response,
      interface power-change request / response, vendor specific)
- [x] Round-trip property tests via Hypothesis (CMDU header + body, plus
      per-TLV strategies)
- [x] Committed regression fixture (`tests/fixtures/baseline_1905.pcap`)
      built from `tests.fixtures.build_baseline_pcap`, covers every
      registered TLV; regenerable on demand
- [x] Coverage gate: assertion that every `TLVType` enum value has a
      registered handler
- [ ] (deferred to bonus) `tshark -V` cross-validation in CI — see
      EXPLORATION D.2; current regression fixture covers drift detection
      between code changes

## Phase 2 — EasyMesh R1–R4 TLV layer

- [x] **R1 TLVs** (36 types, `0x80`–`0xA3`) — covered in
      `src/ieee1905/core/tlvs/easymesh_r1.py`:
      SupportedService / SearchedService, AP Radio Identifier,
      AP Operational BSS, Associated Clients, AP Radio Basic Capabilities,
      AP HT / VHT / HE Capabilities, Steering Policy, Metric Reporting
      Policy, Channel Preference, Radio Operation Restriction,
      Transmit Power Limit, Channel Selection Response, Operating Channel
      Report, Client Info, Client Capability Report, Client Association
      Event, AP Metric Query, AP Metrics, STA MAC Address Type,
      Associated STA Link Metrics, Unassociated STA Link Metrics
      Query / Response, Beacon Metrics Query / Response, Steering Request,
      Steering BTM Report, Client Association Control Request,
      Backhaul Steering Request / Response, Higher Layer Data, AP
      Capability, Associated STA Traffic Stats, Error Code.
- [x] R1 message types (27 types, `0x8000`–`0x801A`) added to
      `MessageType`.
- [x] R1 regression fixture (`tests/fixtures/easymesh_r1.pcap`,
      regenerable via `tests.fixtures.build_easymesh_r1_pcap`).
- [x] **R2 TLVs** (25 types, `0xA4`–`0xCC`) — covered in
      `src/ieee1905/core/tlvs/easymesh_r2.py`:
      Channel Scan Reporting Policy / Capabilities / Request / Result,
      Timestamp, 1905 Layer Security Capability, Profile-2 AP
      Capability, Default 802.1Q Settings, Traffic Separation Policy,
      Profile-2 Error Code, AP Radio Advanced Capabilities, Association
      Status Notification, Source Info, Tunneled Message Type, Tunneled,
      Profile-2 Steering Request, Unsuccessful Association Policy,
      Metric Collection Interval, Radio Metrics, AP Extended Metrics,
      Associated STA Extended Link Metrics, Status Code, Reason Code,
      Backhaul STA Radio Capabilities, AKM Suite Capabilities.
- [x] R2 regression fixture (`tests/fixtures/easymesh_r2.pcap`,
      regenerable via `tests.fixtures.build_easymesh_r2_pcap`).
- [ ] Profile-2 32-bit TLV length framing — deferred (no observed wild
      device today needs it; standard 2-byte length covers all R2 TLVs
      below 64 KB and we can add a Profile-2 framer when a real device
      requires it).
- [x] **R3 TLVs** (15 types, `0xCD`–`0xDF`) — covered in
      `src/ieee1905/core/tlvs/easymesh_r3.py`:
      1905 Encap DPP / EAPOL, DPP Bootstrapping URI Notification,
      Backhaul BSS Configuration, DPP Message / CCE Indication / Chirp
      Value, BSS Configuration Report, BSSID, Service Prioritization
      Rule, DSCP Mapping Table, BSS Configuration Request / Response,
      Device Inventory, Agent List.
- [x] R3 message types added (`0x801F`–`0x8043` selection: Proxied /
      Direct Encap DPP, BSS Configuration Request / Response / Result,
      Chirp Notification, 1905 Encap EAPOL, Reconfig Trigger, …).
- [x] R3 regression fixture (`tests/fixtures/easymesh_r3.pcap`).
- [x] **R4 TLVs** (10 types, `0xAB` + `0xE0`–`0xE8`) — covered in
      `src/ieee1905/core/tlvs/easymesh_r4.py`:
      AP Wi-Fi 6 Capabilities, AP EHT Operations / EHT Operations,
      AP Wi-Fi 7 Agent Capabilities (per-radio EMLSR/EMLMR/NSTR/STR),
      Agent AP / Backhaul STA / Associated STA MLD Configuration
      (with AffiliatedLink sub-records), Affiliated STA Metrics,
      Affiliated AP Metrics, TID-to-Link Mapping Policy.
- [x] R4 message types added (Available Spectrum Inquiry / Response,
      QoS Management Notification).
- [x] Every TLV carries a `spec_ref` metadata string
      (`Multi-AP vX.Y §17.2.NN`).
- [x] R4 regression fixture (`tests/fixtures/easymesh_r4.pcap`).
- [x] **Phase 2 ✓ complete** — total: 86 EasyMesh TLVs across R1-R4
      registered with the codec (R1 36 + R2 25 + R3 15 + R4 10).

## Phase 3 — Capture & inject I/O ✓ done (core)

- [x] Cross-platform live interface listing (Phase 0)
- [x] BPF filter: default `ether proto 0x893a`; relaxed in bridge mode
- [x] PCAP / PCAPNG read (interface metadata, timestamps) via
      `ieee1905.io.pcap.iter_pcap`
- [x] Inject: single packet + N-repeat, via CLI (`ieee1905 inject`) and
      REST (`POST /api/inject`)
- [x] CLI: `ieee1905 read` (table + summary), `ieee1905 inspect <pcap> N`
      (typed TLV tree)
- [x] REST `POST /api/pcap/decode` (upload + decoded JSON)
- [x] WebSocket `/ws/frames/{interface}` (token handshake, threaded
      sniffer pumping decoded frame JSON to clients)
- [ ] PCAP replay (timing-preserving or accelerated) — deferred to
      v0.2.1+
- [ ] Template library (`templates/*.yaml`) — deferred; for now the CLI
      `inject` accepts a hex blob, and the codec lets callers build any
      CMDU programmatically

## DUT emulator (ADR-013) — minimal core ✓ done

- [x] `src/ieee1905/emulator/agent.py` — fake EasyMesh agent
  - Sends Topology Discovery every 5 s, AP-Autoconfig Search every 30 s
  - Replies to Topology Query → Topology Response (AL MAC + Device Info)
  - Replies to AP Capability Query → Capability Report (radio basic caps
    + operational BSS + supported role/freq band)
  - Replies to AP Metrics Query → Metrics Response
  - Re-triggers autoconfig on Renew
- [x] `src/ieee1905/emulator/controller.py` — fake EasyMesh controller
  - Sends Topology Discovery every 5 s
  - Replies to AP-Autoconfig Search → Autoconfig Response (registrar
    role, mirrored freq band)
  - Issues Topology Query in response to Topology Notification
  - ACKs AP Capability Reports
- [x] CLI: `ieee1905 emulator agent <iface>`, `ieee1905 emulator controller <iface>`
- [ ] (later) WSC encapsulation and DPP onboarding flow (deferred until
      we have real-DUT lab time)

## Phase 4 — Bridge / MITM engine

- [ ] Select two interfaces (in the UI)
- [ ] Bridging loop: A → (decode → rules → re-encode) → B and B → A
- [ ] **Non-1905 traffic** is forwarded untouched
- [ ] **1905 traffic** is parsed, run through rules / intercept,
      re-encoded, and forwarded
- [ ] Modification engine:
  - **Rule engine** (YAML):
    ```yaml
    - name: "Strip AL MAC from Topology Discovery"
      match:
        message_type: 0x0000  # Topology Discovery
        direction: a_to_b
      action:
        remove_tlv: 0x01
    - name: "Tamper supported service"
      match:
        tlv_type: 0x80
      action:
        set_field: { path: "supported_services[0]", value: 0xFF }
    ```
  - **Interactive intercept** (Burp-style): toggle in UI, a captured
    frame is forwarded to the frontend over WS, the user edits it and
    chooses forward / drop
  - **Drop / delay / duplicate** as rule actions
- [ ] Hot-reload of rules (file watcher)
- [ ] Modification log: before / after diff of every changed frame

## Phase 5 — TLV plugin system (user extensions)

- [ ] Plugin directories:
  - `~/.config/ieee1905-suite/tlv_plugins/`
  - `./tlv_plugins/` (project-local)
- [ ] **YAML declarative format**:
  ```yaml
  - tlv_type: 0xE0
    name: "Vendor X Custom Telemetry"
    vendor_oui: "001A2B"  # when inside a vendor-specific TLV
    fields:
      - { name: "version", type: "u8" }
      - { name: "sample_count", type: "u16" }
      - { name: "samples", type: "array", element: "u32",
          count_from: "sample_count" }
      - { name: "label", type: "string", length: "remaining" }
  ```
- [ ] **Python plugin format** (for complex parsing):
  ```python
  from ieee1905.plugins import register_tlv, TLVPlugin

  @register_tlv(tlv_type=0xE1, name="Vendor Y FSM State")
  class VendorYFSM(TLVPlugin):
      def decode(self, payload: bytes) -> dict: ...
      def encode(self, data: dict) -> bytes: ...
      def describe(self) -> list[Field]: ...
  ```
- [ ] OUI-based sub-dispatch inside vendor-specific TLV (`0x0B`)
- [ ] Unknown TLV → "Unknown" + hex / ASCII view + "Write a plugin" CTA
- [ ] In-UI plugin manager (add / edit / remove / reload, hot reload)
- [ ] Plugin schema validation + security (Python plugins opt-in)

## Phase 6 — Conformance test harness

- [ ] Test scripts (YAML): "send X → wait for Y → verify TLV Z"
  ```yaml
  test: "TC-1905-TopoDiscovery-Basic"
  spec: "IEEE 1905.1-2013 §6.3.1"
  steps:
    - send: { template: topology_discovery }
    - expect:
        within_ms: 1000
        message_type: 0x0001  # Topology Notification
        contains_tlv: [0x01, 0x07]
    - assert:
        tlv: 0x01
        field: al_mac
        equals: "{{ dut.al_mac }}"
  ```
- [ ] Runnable from the UI **and** `python -m ieee1905.test_runner`
- [ ] JUnit XML + HTML reports (CI-friendly)
- [ ] Pre-bundled suites:
  - 1905.1 baseline
  - EasyMesh R1 conformance
  - EasyMesh R2 conformance
  - EasyMesh R3 conformance
  - EasyMesh R4 conformance
- [ ] Negative tests (malformed input, fragmentation edge cases, …)
- [ ] **Coverage tracker**: which TLV / message types were actually
      exercised?

## Phase 7 — Web UI

- [ ] FastAPI backend:
  - REST: list devices / interfaces, start / stop capture, manage
    plugins, run tests, fetch reports
  - WebSocket: live frame stream, intercept events
  - Auth: random token, printed in the CLI on first launch
  - CORS: localhost only
- [ ] Vue 3 + TypeScript + PrimeVue + Vite frontend:
  - **Capture view**: 3-pane (packet list / TLV tree / hex)
  - **Inject view**: pick a template, edit fields, send
  - **Bridge view**: select two interfaces, start, watch live modifications
  - **Intercept view**: Burp-style hold / edit
  - **Rules view**: YAML editor with syntax highlight, validate, save
  - **Plugins view**: TLV plugin manager
  - **Tests view**: run conformance suite, inspect results, drill down
  - **Settings**: theme, language (EN / TR), config files
- [ ] Dark / light theme
- [ ] Packet diff view (compare two packets / two captures)

## Phase 8 — Polish & distribution

- [ ] `pipx install ieee1905-suite` one-command install
- [ ] `.deb` (Debian / Ubuntu), `.dmg` (macOS), `.msi` / portable EXE
      (Windows)
- [ ] Optional single-binary build via PyInstaller
- [ ] Wireshark Lua dissector export (side-product, ecosystem contribution)
- [ ] Docs: user guide (mkdocs), API reference, spec mapping table
- [ ] Localization: TR + EN (UI)
- [ ] First public release: `v0.1.0`

---

## Dependencies (planned)

**Python (Phases 0–6)**:
- `scapy` (initial backend; migration to libpcap planned)
- `pcapy-ng` or `python-libpcap` (later phase)
- `fastapi`, `uvicorn[standard]`, `websockets`
- `pydantic` (config + API models)
- `pyyaml`
- `rich` (CLI output)
- `pytest`, `pytest-asyncio`, `hypothesis` (dev)
- `ruff`, `mypy` (dev)

**Frontend**:
- Vue 3, TypeScript, Vite, PrimeVue, Pinia (state), vue-router, vue-i18n

**System**:
- Linux: `libpcap-dev` (build), `libcap2-bin` (setcap)
- macOS: ChmodBPF (ships with Wireshark)
- Windows: Npcap (documented in CONTRIBUTING)

---

## Open questions / to be resolved later

- [ ] If EasyMesh R5 has shipped, is it in scope? (Currently R1–R4, with
      R4 fully covered.)
- [ ] Telemetry / analytics — opt-in or absent? (Default: absent.)
- [ ] Update mechanism (auto-update vs. package manager)
- [ ] DUT inventory / known-device DB? (Vendor OUI → device name lookup)
- [ ] mDNS / DHCP / LLDP correlation view (see [EXPLORATION.md](EXPLORATION.md))

---

## Release plan (revised after ADR-011..016)

**v0.1.0 — "Analyzer + plugins"** (debug + research focus)
- Phase 0: foundations
- Phase 1: 1905.1 core codec + all baseline TLVs
- Phase 3: capture (live + PCAP / PCAPNG) + basic injection
- Phase 5: TLV plugin system (YAML + Python)
- Phase 7 (partial): analyzer view (3-pane + bidirectional hex highlight
  + display filter language + keyboard nav + diff view) —
  **professional UI bar**
- i18n scaffolding (EN + TR)
- **Not in this release:** bridge / MITM, conformance suite, emulator,
  EasyMesh

**v0.2.0 — "EasyMesh R1 + interop"** (interop testing focus)
- Phase 2 (R1): EasyMesh R1 TLVs and message types
- Phase 4: bridge / MITM engine + YAML rules + Burp-style intercept UI
- Phase 6: conformance harness baseline (spec-derived tests, 1905.1 +
  EM R1)
- **DUT emulator (ADR-013)**: minimal fake controller + fake agent
- Phase 7 (continued): bridge UI, intercept queue UI, rule editor,
  test runner UI

**v0.3.0 — "EasyMesh complete + ecosystem"**
- Phase 2 (R2 / R3 / R4): remaining EasyMesh TLVs, profile-2 length,
  EHT / MLD
- Emulator WSC + DPP onboarding support
- Bonus features (from EXPLORATION.md): topology graph (A.1), link
  metric time-series (A.2), OUI DB (C.2), tshark cross-validation
  (D.2), fuzz mode (B.1), coverage tracker (B.3)

**v0.4.0+** — community-driven (plugin marketplace, Lua dissector export,
remote agent, Docker image, sequence diagram view, …)
