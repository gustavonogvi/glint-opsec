# Glint — Planning

## Product Vision

> "The more unique your trail, the easier you are to hunt."

Glint is a local OPSEC assessment tool that answers one simple question:
**are you exposed?**

The tool collects browser and network data, cross-references external intelligence databases,
calculates a multi-dimensional risk score, and delivers a personalized hardening guide.

---

## Epics

### Epic 1 — Browser Fingerprint Collection
**Goal:** Capture, via JavaScript, all the vectors trackers use to identify a browser.

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU1 [done]        | As a user, when I open the tool, my canvas fingerprint is collected automatically | `canvas_hash` present in the payload sent to the backend |
| HU2 [done]        | As a user, my AudioContext fingerprint is collected | `audio_hash` present in the payload |
| HU3 [done]        | As a user, my installed font list is enumerated | `fonts[]` detected, `font_groups[]` with software signatures (ms_office, adobe_cc, coding, etc.), `fonts_blocked` flag if browser normalizes measurements |
| HU4 [done]        | As a user, `navigator` properties are collected | UA, language, platform, hardwareConcurrency, timezone present |
| HU5 [done]        | As a user, screen vs. window geometry is captured | `screen_width`, `window_inner_width` are distinct (when toolbar is present) |
| HU6 [done]        | As a user, WebRTC attempts to collect my real IP | `webrtc.local_ips[]` populated if WebRTC is not blocked |
| HU7 [done]        | As a user, WebGL vendor/renderer is collected | `webgl.vendor` and `webgl.renderer` present |
| HU8 [done]        | As a system, all collectors run in parallel and the payload is sent to the backend | `Promise.all()` → POST in < 3s |

---

### Epic 2 — Network Leak Detection
**Goal:** Detect identity leaks at the network layer (WebRTC, DNS, HTTP headers).

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU9 [done]  | As a user, I know if my real IP leaks via WebRTC even with a VPN | Finding `WEBRTC_LEAK` with severity CRITICAL when private IP is exposed |
| HU10 [pending] | As a user, I know if my DNS resolver belongs to my ISP (DNS leak) | Finding `DNS_LEAK` with severity HIGH when resolver is not a known clean one |
| HU11 [done] | As a system, the backend analyzes inconsistencies in HTTP headers | Finding `HEADER_LANG_MISMATCH` when Accept-Language differs from navigator.language |
| HU12 [done] | As a system, the backend detects timezone inconsistency | Finding `TIMEZONE_MISMATCH` when JS offset doesn't match geolocation-inferred timezone |

---

### Epic 3 — OSINT & Breach Intelligence
**Goal:** Cross-reference identity data with external breach and reputation databases.

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU13 | As a user, I can check if my email was exposed in breaches (opt-in) | POST /api/osint returns breach list from HIBP |
| HU14 | As a user, the email check uses k-anonymity (full email is never sent) | Only the first 5 chars of the SHA-1 hash are sent to HIBP |
| HU15 [done] | As a system, the user's IP is queried on ip-api.com | `server_observed.ip_reputation` contains country, ISP, proxy flag |
| HU16 | As a system, IPs with high AbuseIPDB score generate a finding | Finding `IP_ABUSE_HIGH` when confidence > 50 (if API Key is configured) |
| HU17 [done] | As a system, an external API failure does not break the scan | Dimension score = 0 (neutral), INFO finding explaining unavailability |

---

### Epic 4 — Risk Engine
**Goal:** Transform raw collected data into actionable risk scores.

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU18 [done] | As a system, each dimension produces a score from 0 to 100 | `dimensions[].score` always between 0 and 100 |
| HU19 [done] | As a system, the composite score is calculated with configurable weights | `composite_score = Σ(score × weight)` using weights from config |
| HU20 [done] | As a system, the composite score maps to a risk level | CRITICAL/HIGH/MEDIUM/LOW per defined thresholds |
| HU21 [done] | As a system, findings are generated with severity and evidence | Each finding has: `finding_key`, `severity`, `title`, `description`, `evidence{}` |
| HU22 [done] | As a system, the uniqueness score (entropy) is calculated separately | `identity_entropy_score` in bits, displayed separately from risk level |
| HU23 [pending] | As a user, I receive a personalized hardening guide | Recommendations list ordered by priority, specific to my findings |

---

### Epic 5 — Dashboard & Visualization
**Goal:** Present results in a clear, technical, and impactful way.

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU24 | As a user, I see a radar chart with the 4 risk dimensions | Chart.js RadarChart renders with colors mapped to severity |
| HU25 | As a user, I see each finding with a colored severity badge | CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green, INFO=gray |
| HU26 | As a user, I see the hardening guide with specific steps | Each recommendation has a title, numbered steps, and references |
| HU27 | As a user, I can view my previous scan history | GET /api/scans → table with scan_id, date, IP, risk_level |
| HU28 | As a user, the UI follows a dark terminal aesthetic | CSS with dark background, monospace font, terminal colors |

---

### Epic 6 — Persistence & Packaging
**Goal:** Ensure the tool is installable, portable, and maintains local history.

**User Stories:**

| ID   | Story | Acceptance Criteria |
|------|-------|---------------------|
| HU29 [done] | As a user, the SQLite database is created automatically on first run | `create_tables()` runs on startup without errors |
| HU30 | As a user, each scan is persisted with the full payload | `scans` table contains raw_payload and result_json |
| HU31 [done] | As a user, I can install with `pip install -e .` | pyproject.toml is valid and dependencies resolve |
| HU32 [done] | As a user, I can run with `python -m glint` | Entry point works from any directory |
| HU33 | As a user, I configure API keys via `.env` file | `HIBP_API_KEY` and `ABUSEIPDB_API_KEY` loaded via python-dotenv |

---

## Phase Roadmap

```
Phase 0 — Scaffolding
├── pyproject.toml ✓
├── .env.example ✓
├── .gitignore ✓
├── acheron/app.py         Flask factory + main()
├── acheron/config.py
└── acheron/db/migrations.py

Phase 1 — JS Collectors                            [Epic 1]
├── static/js/collectors/canvas.js
├── static/js/collectors/audio.js
├── static/js/collectors/fonts.js
├── static/js/collectors/navigator.js
├── static/js/collectors/screen.js
├── static/js/collectors/webrtc.js
├── static/js/core/fingerprint.js
├── static/js/core/submit.js
└── templates/index.html

Phase 2 — Backend + Risk Engine                    [Epic 2 partial + Epic 4]
├── acheron/api/fingerprint.py
├── acheron/collectors/http_headers.py
├── acheron/collectors/ip_reputation.py
├── acheron/engine/entropy.py
├── acheron/engine/dimensions.py
├── acheron/engine/risk.py
└── acheron/db/repository.py

Phase 3 — DNS Leak + HIBP                          [Epic 2 complete + Epic 3]
├── acheron/collectors/dns_leak.py
├── acheron/collectors/hibp.py
└── acheron/api/osint.py

Phase 4 — Dashboard                                 [Epic 5]
├── templates/results.html
├── templates/history.html
├── static/js/dashboard/radar.js
├── static/js/dashboard/findings.js
├── acheron/engine/hardening.py
└── acheron/api/scan.py

Phase 5 — Polish                                    [Epic 6]
├── static/css/dashboard.css
└── End-to-end validation
```

---

## Phase Dependencies

```
Phase 0 → Phase 1 (Flask must be running to test the POST)
Phase 1 → Phase 2 (JS payload needed to implement the intake endpoint)
Phase 2 → Phase 3 (scorers already working; adds more collectors)
Phase 2 → Phase 4 (dashboard consumes the Phase 2 JSON)
Phase 4 → Phase 5 (polish only after everything is functional)
```

---

## Findings Catalogue

Complete list of findings the system can generate:

| finding_key            | Dimension     | Severity | Trigger                                                   |
|------------------------|---------------|----------|-----------------------------------------------------------|
| `WEBRTC_LEAK`          | network       | CRITICAL | Private IP exposed via ICE candidates                     |
| `WEBRTC_VPN_BYPASS`    | network       | HIGH     | Public IP via STUN differs from request IP                |
| `DNS_LEAK`             | network       | HIGH     | System resolver is ISP, not VPN/DoH                       |
| `HEADER_LANG_MISMATCH` | network       | MEDIUM   | Accept-Language ≠ navigator.language                      |
| `TIMEZONE_MISMATCH`    | network       | MEDIUM   | JS timezone inconsistent with IP geolocation              |
| `CANVAS_UNIQUE`        | anonymity     | HIGH     | Canvas hash is rare (< 1% of known samples)               |
| `AUDIO_UNIQUE`         | anonymity     | MEDIUM   | Audio hash is rare                                        |
| `FONT_COUNT_HIGH`      | anonymity     | MEDIUM   | Too many installed fonts (> 80)                           |
| `WEBGL_SPECIFIC`       | anonymity     | MEDIUM   | Specific and identifiable GPU renderer                    |
| `UA_INCONSISTENT`      | anonymity     | LOW      | Unusual or inconsistent User-Agent                        |
| `BREACH_FOUND`         | data_exposure | HIGH     | Email found in ≥ 1 HIBP breach                            |
| `BREACH_PASSWORD`      | data_exposure | CRITICAL | Breach includes passwords                                 |
| `BREACH_FINANCIAL`     | data_exposure | CRITICAL | Breach includes financial data                            |
| `IP_ABUSE_HIGH`        | ip_reputation | HIGH     | AbuseIPDB confidence score > 50                           |
| `IP_HOSTING`           | ip_reputation | LOW      | Datacenter/hosting IP (unusual for a browser)             |
| `NO_EMAIL_CHECKED`     | data_exposure | INFO     | User did not provide email for breach check               |
| `API_UNAVAILABLE`      | (any)         | INFO     | External API unavailable — degraded score                 |
