# Changelog

All notable changes to this project will be documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Profile-2 32-bit TLV length framing** — `extended_length=True` on
  `RawTLV.to_bytes`/`from_bytes` and `profile=2` on `CMDU.to_bytes`/
  `from_bytes` switch the wire format to the Multi-AP v2.0 5-byte TLV
  header. Defaults stay at 2-byte length so every existing caller
  keeps working. 10 new tests cover round-trips in both modes and
  cross-mode decode failures (120 total passing).
- **DUT emulator ✓ core complete** (ADR-013) — `src/ieee1905/emulator/`:
  - `FakeAgent`: periodically emits Topology Discovery (5 s) and
    AP-Autoconfig Search (30 s); replies to inbound Topology Query,
    AP Capability Query, AP Metrics Query, and AP-Autoconfig Renew.
  - `FakeController`: emits Topology Discovery (5 s); replies to
    AP-Autoconfig Search (mirroring the requested freq band) and
    Topology Notification (issues Topology Query back); ACKs AP
    Capability Reports.
  - Shared `_common.py` with the build_cmdu / send_frame / sniff loop
    plumbing; both emulators run a daemon sniff thread and a daemon
    heartbeat thread keyed on a `threading.Event` stop signal.
  - CLI: `ieee1905 emulator agent <iface>` and
    `ieee1905 emulator controller <iface>` with sensible MAC defaults.
  - 4 new tests (110 total passing): the response-building logic is
    exercised against a mocked `send_frame` so the tests don't need a
    privileged socket — they decode the produced frame back to verify
    the emitted message type and TLV set.
  - WSC encapsulation and DPP onboarding deferred until we have a real
    device on the bench to validate against.
- **Phase 3 ✓ core complete** — capture / inject I/O surface:
  - `src/ieee1905/io/pcap.py`: `iter_pcap()` yields `CapturedFrame`
    records (timestamp, src/dst MAC, ethertype, decoded `CMDU` or
    parse error). `summarize_pcap()` returns a message-type histogram.
  - CLI: `ieee1905 read <pcap>` (table view), `... --summary`
    (histogram), `ieee1905 inspect <pcap> N` (typed TLV tree for one
    frame), `ieee1905 inject <iface> --frame-hex ...`.
  - REST: `POST /api/pcap/decode` accepts an uploaded PCAP and
    returns JSON with decoded frames, including typed TLV fields
    (bytes rendered as hex, nested dataclasses unfolded).
  - WebSocket: `/ws/frames/{interface}` opens a token-authenticated
    live stream of decoded 1905 frames, with backpressure-bounded
    queue and a clean shutdown path.
  - REST: `POST /api/inject` takes `{interface, frame_hex, repeat,
    dst_mac, src_mac?}` and writes the frame onto the wire.
  - 9 new tests (106 total passing): PCAP iterator, CLI commands,
    REST decode/auth/validation paths.
  - Added `python-multipart` runtime dep for FastAPI's `UploadFile`.
- **Phase 2 ✓ complete** — EasyMesh R4 TLV layer (Wi-Fi 7 / EHT / MLD):
  - 10 R4 TLVs (`0xAB` + `0xE0`–`0xE8`) implemented in
    `src/ieee1905/core/tlvs/easymesh_r4.py`:
    AP Wi-Fi 6 Capabilities (HE per-role), AP / aggregate EHT
    Operations (with optional EHT operation info bytes, 4-byte EHT
    MCS NSS set, disabled subchannel bitmap), AP Wi-Fi 7 Agent
    Capabilities (per-radio EMLSR/EMLMR/NSTR/STR flags), Agent AP /
    Backhaul STA / Associated STA MLD Configuration sharing a common
    affiliated-link list, Affiliated STA / AP Metrics for MLO,
    TID-to-Link Mapping Policy (8 TIDs × bitmap).
  - 3 R4 message types added (Available Spectrum Inquiry / Response,
    QoS Management Notification).
  - Regression fixture: `tests/fixtures/easymesh_r4.pcap`.
  - 6 new tests (97 total passing). Added a project-wide coverage
    test that asserts every `TLVType` enum value has a handler.
  - **Phase 2 total:** 86 EasyMesh TLVs across R1-R4 registered with
    the codec (R1 36 + R2 25 + R3 15 + R4 10).
- **Phase 2 (R3 slice) complete** — EasyMesh R3 TLV layer:
  - 15 R3 TLVs (`0xCD`–`0xDF`) implemented in
    `src/ieee1905/core/tlvs/easymesh_r3.py` (DPP onboarding, BSS
    configuration request/response/report, BSSID, service
    prioritization rules, DSCP mapping table, device inventory with
    chipset-vendor sub-records, agent list).
  - 14 R3 message types added to `MessageType` (Proxied / Direct
    Encap DPP, BSS Config Request / Response / Result, Chirp
    Notification, 1905 Encap EAPOL, Reconfig Trigger, …).
  - Opaque-payload TLVs (DPP frames, EAPOL frames, BSS configuration
    objects) are stored as `bytes`; a future plugin can dissect them.
  - Regression fixture: `tests/fixtures/easymesh_r3.pcap` (15 frames).
  - 5 new tests (91 total passing). R3 coverage gate added.
- **Phase 2 (R2 slice) complete** — EasyMesh R2 TLV layer:
  - 25 R2 TLVs (`0xA4`–`0xCC`) implemented in
    `src/ieee1905/core/tlvs/easymesh_r2.py` (channel scan, Profile-2
    capability, traffic separation, security capability, tunneled
    messages, radio/STA extended metrics, status/reason codes,
    backhaul-STA radio capabilities, AKM suite capabilities).
  - 11 R2 message types (`0x801B`–`0x8033`) added to `MessageType`.
  - Optional-field TLVs (BSS Load on scan neighbor, backhaul STA MAC on
    backhaul radio capabilities) round-trip in both shapes.
  - Regression fixture: `tests/fixtures/easymesh_r2.pcap` (25 frames,
    ~1.5 KB).
  - 8 new tests (86 total passing). R2 coverage gate added.
  - Profile-2 32-bit TLV length framing intentionally deferred.
- **Phase 2 (R1 slice) complete** — EasyMesh R1 TLV layer:
  - 36 R1 TLVs (`0x80`–`0xA3`) implemented in
    `src/ieee1905/core/tlvs/easymesh_r1.py` (service, identification,
    operational BSS, capability, channel, client, metric, steering,
    misc). Bit-packed capability flags (HT/VHT/HE/AP Capability)
    exposed via named accessors.
  - 27 R1 message types (`0x8000`–`0x801A`) added to `MessageType`.
  - Sub-record dataclasses (BSS, operating-class capability, link
    entries, steering targets, etc.) round-trip cleanly.
  - Regression fixture: `tests/fixtures/easymesh_r1.pcap` (36 frames,
    ~2.2 KB), regenerable via `tests.fixtures.build_easymesh_r1_pcap`.
  - 10 new tests (78 total passing): per-TLV round-trip, fixture wire
    lock, typed decode, accessor sanity checks, optional-field
    variant length (Steering BTM Report), Unknown-TLV fallback in EM
    message context, coverage gate for all `EM_*` types.
- **Phase 1 complete** — 1905.1 core codec:
  - `CMDU` / `CMDUHeader` encode/decode with fragment flags
  - `RawTLV` wire-level TLV parser + `decode_raw` registry dispatch
  - `CMDU.typed_tlvs()` convenience iterator
  - `FragmentReassembler` (per-source MID keying, stale eviction)
  - All 30 IEEE 1905.1 baseline TLVs as typed dataclasses
  - `MessageType` / `TLVType` enums covering the full 1905.1 set
  - `EthernetFrame` helper (with 802.1Q strip) for capture-side glue
  - Committed PCAP fixture (`tests/fixtures/baseline_1905.pcap`) +
    regression tests + coverage assertion (every `TLVType` has a handler)
  - 68 tests passing (round-trip, Hypothesis properties, fragment
    edge cases, fixture decode)
- Phase 0 scaffolding: project layout, `pyproject.toml`, GPLv2 license.
- Python package skeleton (`ieee1905.core`, `ieee1905.io`, `ieee1905.plugins`,
  `ieee1905.modify`, `ieee1905.bridge`, `ieee1905.conformance`,
  `ieee1905.api`, `ieee1905.cli`).
- Cross-platform packet I/O backend abstraction with a Scapy-based default.
- Privilege detection helper (Linux/macOS/Windows).
- FastAPI backend skeleton with token-based auth and CORS for the dev server.
- CLI: `ieee1905 interfaces`, `ieee1905 privileges`, `ieee1905 serve`.
- TLV plugin registry skeleton (Python-decorator path).
- Vue 3 + Vite + TypeScript + PrimeVue + vue-i18n frontend scaffold
  (EN primary, TR secondary).
- GitHub Actions CI matrix (Ubuntu/macOS/Windows × Python 3.11/3.12).
- Pre-commit hooks (ruff, ruff-format, mypy, basic file hygiene).
- Roadmap, architecture decision records, and exploration notes.
