# Project Brief: Continuous L2 Network Security Validation Pipeline

## 1. Project Motivation & Framing

This is a personal cybersecurity project born from wanting to understand and defend against
Layer 2 (Data Link Layer) network attacks — the kind that exploit trust-based protocols like
ARP and switch MAC learning, which have no built-in authentication. Rather than just writing
attack scripts, the goal is to build both the **offense** (attack simulation) and the
**defense** (detection daemons), then wrap the whole thing in a **continuous testing pipeline**
so that detection logic is automatically validated every time the code changes — mirroring how
real DevSecOps teams do continuous security regression testing.

**Core idea in one sentence:** simulate common L2 attacks in a disposable virtual network,
build detectors for each, and use a test automation framework + CI/CD to continuously prove
the detectors work.

## 2. Tech Stack & Why Each Piece Exists

| Technology | Role | Why it's needed |
|---|---|---|
| **Docker + Docker Compose** | Builds the virtual network topology | Need multiple isolated "hosts" (attacker, victim, gateway/switch-sim) on the same virtual L2 network. Compose spins the whole topology up/down with one command — required so Jenkins can automate it. |
| **Scapy** (Python) | Crafts and sends raw L2/L3 packets | This is the attack engine — the open-source stand-in for expensive hardware traffic generators (e.g. IXIA). Used to build ARP replies, DHCP packets, and raw Ethernet frames byte-by-byte. |
| **Custom Python detection daemons** | Passive sniffers + anomaly logic | Sit in "listen mode" (also via Scapy) watching traffic, applying rules to flag anomalous behavior (e.g. IP→MAC binding changes, abnormal MAC growth rate per port). This is the actual security engineering part of the project. |
| **pytest** | Test automation framework | Each attack becomes a test case: launch the attack via Scapy → wait → assert the detector logged it. This is the literal "automated functional/regression testing" the role requires, just aimed at security scenarios. |
| **SQLite** (or Postgres later) | Test result / event logging | Every test run writes: attack type, timestamp, detected (yes/no), response time, severity. Satisfies "SQL/NoSQL for test data logging." Also feeds the optional dashboard. |
| **Jenkins** | CI/CD orchestrator | Watches GitHub via webhook. On every push: spins up the Docker topology → runs the full pytest suite → tears it down → archives an HTML/Allure report. Turns "a script I ran once" into a real continuous validation pipeline. |
| **GitHub** | Version control + Jenkins trigger source | Standard VCS; also the webhook source that kicks off Jenkins builds. |
| **Grafana (optional/stretch)** | Visualizes detection rate & response time trends | Reads from SQLite/Postgres. Ties back to real prior experience with OpenTelemetry/Grafana, keeping this project consistent with existing background rather than looking bolted-on. |

**Clarification on "automation framework" — no AI agent involved.** In this context,
"automation" means pytest running the same test logic repeatedly and mechanically, triggered
by Jenkins on every commit — not an AI/LLM agent making decisions. All detection logic is
deterministic, rule-based Python. This matches how test-automation-engineer roles actually use
the term.

## 3. Attack Modules (Phase 1 — default/common attacks)

Build these three first. Each is a self-contained module with a common interface:
`launch_attack()` and a paired detector with `is_detected()`.

### 3.1 ARP Spoofing (Man-in-the-Middle)
- **Mechanism:** ARP has no authentication. Attacker sends gratuitous ARP replies claiming to
  be the gateway's IP but with the attacker's own MAC. Victim devices trust it and route
  traffic through the attacker.
- **Detection signature (baseline version):** track IP→MAC binding history; flag if an IP's
  bound MAC changes unexpectedly, especially for sensitive IPs (gateway, DNS server).

### 3.2 MAC Flooding (CAM Table Overflow)
- **Mechanism:** switches maintain a CAM table mapping MAC addresses to ports. Attacker floods
  the switch with thousands of fake source MACs, overflowing the table. Many switches
  "fail open" into hub-like broadcast mode, letting the attacker sniff all traffic.
- **Detection signature (baseline version):** abnormally high rate of new/unique MAC addresses
  observed on a single port within a short time window.

### 3.3 Rogue DHCP Server
- **Mechanism:** DHCP has no built-in server authentication. Attacker races the real DHCP
  server with their own; if the attacker's OFFER reaches the victim first, the victim adopts
  the attacker's gateway/DNS, routing traffic through them.
- **Detection signature (baseline version):** any DHCP OFFER arriving from a MAC/port not on
  a pre-defined trusted DHCP server allowlist.

> **Explicitly deferred to Phase 2 (harder/rate-modifying attacks — build after baseline works):**
> - Slow/low-and-slow ARP spoofing (evading rate-based thresholds by pacing spoofed replies)
> - Legitimate binding-change false positives (DHCP renewal, VM migration) needing
>   correlation against the DHCP lease log
> - Slow/paced MAC flooding under fail-open thresholds, requiring per-port historical
>   baselining instead of fixed thresholds
> - VLAN double-tagging hopping (structural frame validation, not rate-based)
> - STP/BPDU root bridge takeover with subtle priority tie-breaking
>
> These are intentionally NOT in the Phase 1 build — they require behavioral baselining and
> state correlation, which only makes sense to build once the simple detectors exist and pass.

## 4. Testing Strategy

Each attack module gets a corresponding pytest test file:

```
test_arp_spoof.py     -> launches ARP spoof attack -> asserts detector logged it, checks latency
test_mac_flood.py     -> launches MAC flood attack -> asserts detector logged it, checks latency
test_rogue_dhcp.py    -> launches rogue DHCP offer -> asserts detector logged it, checks latency
```

Each test should also log its result (pass/fail, response time, timestamp) into the
SQLite results table — this becomes both your test report data and your "security posture"
dashboard data.

## 5. CI/CD Pipeline Flow

```
Developer pushes to GitHub
        ↓
GitHub webhook triggers Jenkins
        ↓
Jenkins: docker-compose up  (spin up attacker / victim / switch-sim containers)
        ↓
Jenkins: run pytest suite (all attack + detection tests)
        ↓
Each test result → written to SQLite (attack_type, detected, response_time_ms, timestamp)
        ↓
Jenkins: archive pytest-html / Allure report as build artifact
        ↓
Jenkins: docker-compose down (teardown)
        ↓
(optional) Grafana dashboard reads SQLite → shows detection rate & response time trend over builds
```

## 6. Proposed Repository Structure

```
l2-security-pipeline/
├── attacks/
│   ├── arp_spoof.py
│   ├── mac_flood.py
│   └── rogue_dhcp.py
├── detectors/
│   ├── arp_detector.py
│   ├── mac_flood_detector.py
│   └── dhcp_detector.py
├── tests/
│   ├── test_arp_spoof.py
│   ├── test_mac_flood.py
│   └── test_rogue_dhcp.py
├── db/
│   └── schema.sql          # results table: id, attack_type, detected, response_time_ms, timestamp, severity
├── docker/
│   ├── docker-compose.yml  # attacker, victim, switch-sim containers on a custom bridge network
│   ├── Dockerfile.attacker
│   └── Dockerfile.victim
├── Jenkinsfile
├── pytest.ini
├── requirements.txt
└── README.md               # architecture diagram, screenshots of passing Jenkins build, writeup
```

## 7. Build Order (Phase 1 MVP)

1. Set up GitHub repo + Docker Compose topology (attacker, victim, switch-sim on custom bridge
   network); verify containers can ping each other.
2. Build `arp_spoof.py` (Scapy attack) + `arp_detector.py` (binding-history watcher).
3. Build `mac_flood.py` + `mac_flood_detector.py` (per-port unique-MAC rate watcher).
4. Build `rogue_dhcp.py` + `dhcp_detector.py` (trusted-server allowlist check).
5. Wire up SQLite schema + logging after each test run.
6. Write pytest suite (`test_arp_spoof.py`, `test_mac_flood.py`, `test_rogue_dhcp.py`).
7. Write Jenkinsfile: docker-compose up → pytest → archive HTML report → docker-compose down.
8. Connect Jenkins to GitHub via webhook (or manual trigger if webhook setup is blocked).
9. README with architecture diagram + screenshot of a passing Jenkins build.

## 8. Framing Note (for README / interview use)

Describe this project as **"a continuous L2 security regression testing pipeline"** —
built out of genuine interest in trust-based protocol vulnerabilities (ARP, DHCP, MAC
learning), with the CI/CD layer added because security detectors should be validated the same
way software is: automatically, on every change. Be explicit in the writeup that the topology
is a simulated/virtual network (Docker), not real hardware or a commercial traffic generator
— that's an honest and still strong claim, and won't fall apart under follow-up questions.
