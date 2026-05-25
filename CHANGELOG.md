# Changelog

All notable changes to this project will be documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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
