# Contributing to ieee1905-suite

Thanks for your interest. This project is **GPL-2.0-or-later**; by submitting
a patch you agree to license it under the same terms.

## Quick start

```bash
git clone <repo>
cd ieee1905-suite
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest -q
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Privileges (live capture / inject)

The backend needs raw socket access. Pick one:

- **Linux**: `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`,
  or run with `sudo`.
- **macOS**: install Wireshark's *ChmodBPF* helper (gives your user access to
  `/dev/bpf*`), or run with `sudo`.
- **Windows**: install [Npcap](https://npcap.com), run the terminal as
  Administrator.

Check with `ieee1905 privileges`.

## Code style

- Python: ruff (lint + format) + mypy `--strict`. Run `ruff check src tests`
  and `mypy src` before pushing.
- TypeScript/Vue: ESLint + `vue-tsc`. Run `npm run lint` and
  `npm run typecheck` in `frontend/`.
- All source files carry an SPDX header:
  `# SPDX-License-Identifier: GPL-2.0-or-later`.

## Commits

We use [DCO](https://developercertificate.org/) — sign off with `git commit -s`.

## Adding a TLV

- **Built-in TLVs** (spec-defined) live in `src/ieee1905/core/tlvs/`. Include a
  `# spec:` comment pointing to the relevant section.
- **User extensions** ship as YAML files in
  `~/.config/ieee1905-suite/tlv_plugins/`, or as Python modules registered via
  `@register_tlv`. See `docs/plugins.md` (Phase 5).

## Reporting bugs

Open an issue with: platform + Python version + minimal repro + a sample
PCAP if possible (`captures/` is gitignored so you can drop one locally).
