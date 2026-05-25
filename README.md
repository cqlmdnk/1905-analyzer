# ieee1905-suite

Cross-platform IEEE 1905.1 + Wi-Fi EasyMesh packet analyzer, injector,
live modifier, and conformance test suite.

**Status:** Planning + Phase 0 scaffolding. No end-user functionality yet.

**License:** GPL-2.0-or-later

---

## Planned features

- **Analyzer:** parse IEEE 1905.1 + EasyMesh R1–R4 packets from a live
  interface or from PCAP / PCAPNG, in a Wireshark-style 3-pane view.
- **Injector:** single packet, template, or scriptable scenarios;
  fault injection (drop / delay / duplicate).
- **Bridge / MITM:** transparent L2 bridge between two interfaces with
  live packet modification (YAML rules + Burp-style interactive
  intercept).
- **Conformance:** spec-mapped test suite that runs both interactively
  (web UI) and headless / in CI.
- **Extensible TLV registry:** add vendor-specific or custom TLVs as
  YAML or Python plugins; unknown TLVs are shown as hex / ASCII.
- **Cross-platform:** Ubuntu 22.04+ LTS (primary), macOS 13+,
  Windows 10+.
- **Web UI:** FastAPI backend + Vue 3 / PrimeVue frontend, served on
  localhost with token auth.

## Documentation

- [`ROADMAP.md`](ROADMAP.md) — phased roadmap, TLV list, dependencies.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — architecture decision records.
- [`EXPLORATION.md`](EXPLORATION.md) — optional / explored features.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to set up and contribute.

## Project layout (planned)

```
ieee1905-suite/
├── src/ieee1905/         # Python package
│   ├── core/             # CMDU + TLV codec
│   ├── io/               # capture / inject (libpcap / Npcap / Scapy)
│   ├── bridge/           # 2-interface MITM engine
│   ├── modify/           # YAML rules + interactive intercept
│   ├── conformance/      # test runner
│   ├── plugins/          # user TLV extensions
│   ├── api/              # FastAPI backend
│   └── cli/              # `ieee1905` command
├── frontend/             # Vue 3 + Vite + PrimeVue
├── tests/
└── docs/
```

## License

Released under the [GNU General Public License v2.0 or later](LICENSE).
