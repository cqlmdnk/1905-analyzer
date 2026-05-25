# Changelog

All notable changes to this project will be documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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
