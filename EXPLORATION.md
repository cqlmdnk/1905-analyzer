# Exploration: additional features and ideas

ROADMAP.md is the phased core plan. This document captures **optional /
worth-investigating** features. For each entry we note its value, the
work involved, the phase it fits, and the trade-offs.

---

## A. Visualization & topology

### A.1 1905 topology graph view
Live graph of every 1905 device + non-1905 neighbor in a multi-device
mesh. Generated automatically from Topology Discovery + Topology
Response TLVs.
- **Value:** Instantly answers "which agent is bound to which
  controller?".
- **Effort:** Medium. networkx + cytoscape.js or vis-network.
- **Phase:** Bonus after Phase 7 (UI).
- **Risk:** Layout jumps when topology changes; needs force-directed
  stabilization.

### A.2 Link metric time-series
Periodically poll link metric Query / Response and plot RSSI /
throughput / errors over time.
- **Value:** Performance regression detection, mesh health monitoring.
- **Effort:** Low (Prometheus-style ring buffer + Chart.js).
- **Phase:** 7+.

### A.3 Sequence diagram view
Render the CMDU exchange between two devices as a sequence diagram
(autoconfig flow, DPP onboarding, …).
- **Value:** While reading the spec, "which step are we at?" becomes
  obvious.
- **Effort:** Medium. mermaid.js or custom SVG.
- **Phase:** 7+.

---

## B. Test & verification power

### B.1 Fuzz mode
TLV length / type / value mutation + reorder + duplicate, fired at a
DUT. Not AFL-style coverage-guided, but smart mutation.
- **Value:** Find robustness bugs (length underflow, infinite
  fragmentation, …).
- **Effort:** Medium. atheris or handwritten.
- **Phase:** After Phase 6.
- **Risk:** DUT may need resets; requires a lab.

### B.2 Symbolic state machine validator
Track the DUT's autoconfig / topology / steering FSMs; flag illegal
state transitions.
- **Value:** Catch "device entered a state the spec forbids".
- **Effort:** High. Define FSMs + map observations to states.
- **Phase:** 8+.

### B.3 Coverage tracker
Which TLV types / message types / spec sections were actually exercised
by tests? Reported per test + a project-wide coverage badge.
- **Value:** Surfaces test gaps.
- **Effort:** Low (instrumentation in the TLV registry).
- **Phase:** Together with Phase 6.

### B.4 Spec metadata embedding
Every TLV carries its spec citation (e.g. "IEEE 1905.1 §17.2.4") +
short description, shown on hover in the UI.
- **Value:** Onboarding for new users; reference during debugging.
- **Effort:** High (manual data entry, one-off).
- **Phase:** Together with Phases 1–2 (add metadata as TLVs are
  implemented).

### B.5 Differential testing
Compare two captures (or two devices); verify that behaviors which
should be equivalent under the spec actually are.
- **Value:** Vendor interop, regression detection.
- **Effort:** Medium.
- **Phase:** 6+.

---

## C. Network context & correlation

### C.1 Side-channel capture (mDNS / LLDP / DHCP)
On the same interface, also capture mDNS (`5353`), LLDP (`0x88cc`), and
DHCP; enrich 1905 device records with hostname / IP / vendor.
- **Value:** Answers "who is MAC `aa:bb:cc:…`?".
- **Effort:** Low (Scapy already parses these).
- **Phase:** 7+ (feeds the "device info" panel in the UI).

### C.2 OUI vendor database
Map MAC OUIs from the Wireshark `manuf` file. Local cache + auto-update.
- **Value:** Device identification.
- **Effort:** Low.
- **Phase:** Together with Phase 1.

### C.3 Wi-Fi side-channel capture
If a monitor-mode-capable Wi-Fi adapter is present, capture beacons /
probes / auth frames alongside 1905 — very useful during onboarding
flows (DPP).
- **Value:** End-to-end visibility into onboarding.
- **Effort:** High (radiotap, channel hopping, per-OS quirks).
- **Phase:** 8+.

---

## D. Developer ergonomics

### D.1 Wireshark Lua dissector export
Generate a Wireshark Lua dissector from our TLV registry, so users see
nicely parsed 1905 packets in their Wireshark.
- **Value:** Ecosystem contribution; integrates with existing Wireshark
  workflows.
- **Effort:** Medium.
- **Phase:** 8, polish.

### D.2 tshark JSON cross-validation
In CI: decode known-good PCAPs with both our codec and tshark; compare
results. Catches regressions.
- **Value:** Continuous assurance of decoder correctness.
- **Effort:** Low.
- **Phase:** 1+.

### D.3 REPL / Python library API
`from ieee1905 import CMDU, TLV; cmdu = CMDU.from_bytes(b"...")` — the
package is also usable as a library.
- **Value:** Quick debugging, custom scripts.
- **Effort:** Low (the codec is already library-shaped).
- **Phase:** Together with Phase 1 (emerges naturally).

### D.4 Plugin marketplace / sharing
Community shares vendor TLV plugins (GitHub repo + simple discovery).
- **Value:** Network effect.
- **Effort:** Medium.
- **Phase:** 8+ (driven by community traction).

### D.5 Command palette (Ctrl+K)
Quick-action palette in the UI.
- **Value:** Power-user speed.
- **Effort:** Low.
- **Phase:** 7.

---

## E. Operations & distribution

### E.1 Remote agent + central UI
Install the backend on a Raspberry Pi (inside the mesh, sniffing
locally); open the UI from a laptop. WireGuard / SSH tunnel.
- **Value:** Field debugging, lab setups.
- **Effort:** Medium (need to harden auth / transport).
- **Phase:** 7+ (the Web UI choice already enables this).

### E.2 Multi-AP controller emulator
Appear as a controller (send autoconfig responses, onboard an agent).
For testing agents.
- **Value:** Test agents without a real controller in the lab.
- **Effort:** High (state machine + DPP / WSC).
- **Phase:** 8+.

### E.3 Multi-AP agent emulator
The inverse: appear as an agent. For testing controllers.
- **Value:** Test controllers without a real agent in the lab.
- **Effort:** High.
- **Phase:** 8+.

### E.4 Docker image
Run the backend in a container (`--net=host --cap-add=NET_RAW
--cap-add=NET_ADMIN`).
- **Value:** Easy CI deployment.
- **Effort:** Low.
- **Phase:** 8.

### E.5 Persistent capture / database
Write long-running captures to a DB (SQLite / DuckDB) and query them
("every packet containing TLV X in the last 24 hours").
- **Value:** Forensic analysis.
- **Effort:** Medium.
- **Phase:** 8+.

---

## F. Advanced protocol capabilities

### F.1 Fragmentation chaos testing
Deliberately broken fragment sequences (missing fragments, duplicate
last-fragment, …).
- **Value:** Check whether the DUT reassembler is robust.
- **Effort:** Low (added as rule actions).
- **Phase:** Integrated into Phase 4 (modification engine).

### F.2 DPP onboarding sniffer
Capture 1905-encapsulated DPP plus DPP chirp / auth frames; visualize
the onboarding flow.
- **Value:** Debug aid for the most complex EasyMesh R3 feature.
- **Effort:** High (DPP is its own protocol).
- **Phase:** 7+.

### F.3 Channel selection visualizer
From EasyMesh channel preference / selection messages, render "what
channels does the mesh use right now?".
- **Value:** RF planning, troubleshooting.
- **Effort:** Medium.
- **Phase:** 7+.

### F.4 Steering decision auditor
Log client steering request / response; answer "why was this client
steered?".
- **Value:** EasyMesh UX debugging.
- **Effort:** Low.
- **Phase:** 7+.

---

## G. Security & integrity

### G.1 Flag whether 1905 traffic is signed / encrypted
Per spec, 1905 traffic is **not** signed (assumes same L2 segment);
an attacker can spoof an AL MAC. The UI surfaces this explicitly and
warns when spoofing is observed.
- **Value:** Security research.
- **Effort:** Low.
- **Phase:** 7+.

### G.2 Plugin sandbox
A restricted Python subset (RestrictedPython) or subprocess isolation
for user TLV plugins.
- **Value:** Safer loading of untrusted plugins.
- **Effort:** High.
- **Phase:** 8+ (together with the community marketplace).

---

## Release plan — moved to ROADMAP.md

The current release breakdown lives at the bottom of
[ROADMAP.md](ROADMAP.md#release-plan--revised-after-adr-011016).
Summary:

- **v0.1.0**: Analyzer + plugins (debug / research) — 1905.1 + capture
  + UI core
- **v0.2.0**: EasyMesh R1 + bridge / MITM + conformance baseline +
  DUT emulator (E.2 / E.3 pulled into v0.2)
- **v0.3.0**: EasyMesh R2 / R3 / R4 in full + bonus features
  (A.1, A.2, B.1, B.3, C.2, D.2)
- **v0.4.0+**: community-driven (D.4, D.1, E.1, A.3, …)
