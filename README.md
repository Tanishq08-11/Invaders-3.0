# AI Insider Threat Detection System: Encrypted Traffic Analysis

An enterprise-grade, AI-powered cybersecurity backend that detects rogue insiders exfiltrating sensitive corporate data by analyzing **encrypted network traffic without decrypting its contents**.

Powered by **Live Network Metadata Sniffing**, **Kitsune's AfterImage Feature Extractor**, an **Ensemble of Autoencoders (KitNET)**, a **Teammate Model Verification & Hot-Swapping Adapter**, a contextual **Risk Engine**, an **Explainable AI (XAI) Engine**, and a high-performance **Flask REST & SSE Streaming Backend** built for Security Operations Center (SOC) dashboards.

---

## 0. Running the Full Stack (Backend + VEYLIX Dashboard)

The VEYLIX frontend (React + Vite) lives in [`frontend/`](frontend/) and talks to this backend on the same origin.

```bash
# 1. Backend
pip install -r requirements.txt
python app.py                       # http://localhost:5000

# 2a. Production-style: build once, Flask serves the UI
cd frontend && npm install && npm run build
#     → open http://localhost:5000

# 2b. Frontend development (hot reload; /api is proxied to :5000)
cd frontend && npm run dev          # → open http://localhost:5173
```

**Portal accounts** live in a separate users database (`instance/veylix_users.db`, override with
`AUTH_DATABASE_URL`). On first start, when it is empty, 20 worker accounts and 2 analyst accounts are created,
each with its own random password. An `ADMIN` account (`admin01`) is added whenever none exists (also for
existing databases). Only scrypt hashes are stored; generated credentials are written to
`instance/worker_credentials.csv` (gitignored). Delete both files and restart to issue a fresh set.

| Role | Usernames | Lands on |
| :--- | :--- | :--- |
| `EMPLOYEE` (20 workers) | `eng01`–`eng04`, `fin01`–`fin04`, `hr01`–`hr04`, `sales01`–`sales04`, `mgmt01`–`mgmt04` | `/employee/dashboard` — file portal |
| `SECURITY_ANALYST` | `analyst01`, `analyst02` | `/soc` — alerts, event log, devices, collector status (read-only) |
| `ADMIN` | `admin01` | `/soc` — everything an analyst sees, plus collector start/stop, PCAP analysis, dataset replay, model management |

To populate the SOC with data: upload/download files as an employee (application events), then as `admin01`
open **Network Collector** and start live capture on an explicitly selected interface, start the clearly
labelled simulation, or analyse a PCAP. The BoT-IoT replay (`POST /api/v1/stream/start`) also still works.
Auth model: an HttpOnly session cookie. SOC reads need `SECURITY_ANALYST` or `ADMIN`, service operations need
`ADMIN`, file routes need `EMPLOYEE`. `/api/v1/health` is public with minimal fields, and `POST /api/v1/events`
is open unless `INGEST_API_KEY` is set. Full route and role table: [docs/API.md](docs/API.md). Pipeline design:
[docs/EVENT_PIPELINE.md](docs/EVENT_PIPELINE.md).

---

## 1. Architectural Workflow

> The authoritative, current description of the event pipeline (application activity, packets, flows,
> correlation, detector boundary, SSE) is [docs/EVENT_PIPELINE.md](docs/EVENT_PIPELINE.md). The diagram
> below shows the detection stages of the original design.

```
       +-------------------------------------------------------------+
       |                  NETWORK TRAFFIC SOURCES                    |
       |  • Live Interface Sniffer (WiFi / Ethernet via Scapy)        |
       |  • Offline PCAP / PCAPNG packet streams                     |
       |  • Benchmark Datasets (BoT-IoT, CIC-IDS, UNSW-NB15, Zeek)    |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |         LIVE NETWORK COLLECTOR (ZERO DECRYPTION)            |
       |  • 5-tuple header extraction: src/dst IP, ports, proto, bytes|
       |  • Operating modes: "live", "simulation", "stopped"          |
       |  • Fault-isolated packet sniffer with corrupted frame skip  |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                     EVENT PROCESSOR                         |
       |  • Invariant: PERSIST RAW EVENT FIRST                       |
       |  • Preserves events with ai_error if model degraded         |
       |  • Atomic database commit with automatic rollback on error  |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |            KITSUNE AFTERIMAGE FEATURE EXTRACTOR             |
       |  • 100 rolling statistical features across 5 decay windows  |
       |  • O(1) space/time per packet, damped incremental stats     |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |             DETECTION ENGINE / MODEL ADAPTER                |
       |  • KitNET Ensemble Autoencoders (hierarchical clustering)   |
       |  • Teammate Model Adapter (PyTorch, Scikit-learn, Custom)    |
       |  • Automated Verification & Dynamic Hot-Swapping            |
       |  • Model delivery decoupled: backend ready for teammate model|
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                   CONTEXTUAL RISK ENGINE                    |
       |  • Dynamic Z-score thresholding against baseline (μ, σ, max)|
       |  • Heuristics: off-hours, external destination, volume      |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                  EXPLAINABLE AI (XAI) ENGINE                |
       |  • Root-cause feature error decomposition                   |
       |  • Human-readable SOC incident narrative & playbook steps   |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                   FLASK REST & SSE BACKEND                  |
       |  • Ingestion, Alerts Triage, Device Timelines, Quarantine   |
       |  • Live SSE Telemetry Feed to Security Dashboard            |
       +-------------------------------------------------------------+
```

---

## 2. Core Security & Privacy Principles

- **Zero Decryption & Privacy Compliance**: Inspecting payload contents violates GDPR, HIPAA, and employee privacy. Furthermore, modern TLS 1.3, Encrypted Client Hello (ECH), and pinned certificates make deep payload inspection impractical.
- **Behavioral Header Dynamics**: Rogue insiders exfiltrating confidential IP produce distinctive statistical anomalies in transport and network headers:
  - High burst velocity and sustained outbound throughput over short time windows ($\lambda = 5.0, 3.0$).
  - MTU frame uniformity (continuous 1400–1500 byte payloads).
  - Outbound-to-inbound asymmetry (heavy upload vs. negligible inbound ACK packets).
  - Low inter-arrival jitter indicative of automated exfiltration scripts.
- **AfterImage O(1) Damped Statistics**: Computes 100 rolling statistical features across multiple decay windows ($\lambda \in [5, 3, 1, 0.1, 0.01]$) covering 100ms micro-bursts to 1-minute macro trends.
- **KitNET Ensemble of Autoencoders**: Uses hierarchical correlation clustering to partition 100 features into small subsets ($m \le 10$), training an ensemble of compact autoencoders plus an aggregator autoencoder.

---

## 3. Live Network Collector & Metadata Extraction

The integrated network collector automatically captures live traffic or replays PCAP traces and streams 5-tuple metadata into the ingestion pipeline:

### Capabilities
- **Explicit Operating Modes**: `stopped`, `starting`, `live` (reported only after Scapy confirms the capture
  socket opened), `simulation` (synthetic packets, every event labelled `source=simulation`), `failed` (start
  failed or the sniffer died; the reason is in `last_collector_error`).
- **Flow aggregation**: bidirectional 5-tuple flows with per-direction counts and bytes, size/inter-arrival
  statistics, TCP flag counts, and idle, active and TCP-close timeouts; memory is bounded (`services/flow_aggregator.py`).
- **TLS handshake metadata**: SNI, versions, ALPN and JA3 from cleartext ClientHello/ServerHello fields. No
  decryption. JA4 is not supported. Optional Zeek enrichment for PCAPs.
- **Zero Decryption Guarantee**: Extracts header metadata without ever decrypting packet payloads or storing their contents:
  ```json
  {
    "timestamp": 1770984000.12,
    "src_ip": "192.168.1.105",
    "dst_ip": "45.33.32.156",
    "src_port": 55120,
    "dst_port": 443,
    "protocol": "TCP",
    "bytes": 1460
  }
  ```
- **Offline PCAP / PCAPNG Ingestion**: Parses `.pcap`, `.pcapng`, or `.cap` capture files directly into the pipeline with strict input validation on `max_packets` and file integrity.
- **No silent fallback**: If live capture cannot start (Npcap missing, privilege denied, unknown or unauthorised
  interface), the collector reports `failed` with the reason. It switches to simulation only when the operator
  explicitly passes `allow_simulation_fallback: true`, and then says so in a warning.

### Command-Line Usage
```bash
# List available network interfaces on the host
python live_collector.py --list-interfaces

# Start live packet capture on a specific adapter with BPF filter (needs Npcap/libpcap + privileges)
python live_collector.py --interface "Wi-Fi" --filter "tcp or udp"

# Process an offline PCAP file
python live_collector.py --pcap sample_traffic.pcap

# Run simulated live packet generation
python live_collector.py --simulate --duration 30
```

---

## 4. Model Management & Teammate Model Integration

The backend includes a pluggable model adapter layer ([services/model_adapter.py](file:///d:/invaders%203.0/services/model_adapter.py)) that validates, benchmarks, and hot-swaps any ML detector:

### Division of Responsibilities
- **Person 4 (Backend)**: Provides the event pipeline, feature extraction, risk scoring heuristics, XAI narratives, REST APIs, SSE feeds, database persistence, and model verification seams.
- **Teammate (ML)**: Responsible for training the custom AI model. The backend is completely decoupled and will integrate the teammate's final checkpoint without architectural modifications.

### Supported Model Formats
1. **KitNET Ensemble Autoencoders** (`.pkl`, `.pt`)
2. **PyTorch Modules** (`torch.nn.Module` or `state_dict` weights)
3. **Scikit-Learn Estimators** (`IsolationForest`, `OneClassSVM`, `RandomForestClassifier`)
4. **Custom Python Callables** `score(vec_100d) -> (anomaly_score, feature_errors)`

### Verification & Dynamic Hot-Swapping
- **Verification Endpoint** (`POST /api/v1/model/verify`):
  - Sends a 100-dimensional calibration vector through the candidate model.
  - Benchmarks inference latency in milliseconds.
  - Verifies that reconstruction error attribution matches input dimension (100-D).
  - Validates numeric stability (no `NaN` or infinite values).
- **Zero-Downtime Hot-Swapping**:
  - Hot-swaps the verified model directly into the live `EventProcessor` pipeline without restarting the server.

---

## 5. Error Handling & System Resilience Architecture

The system implements defensive error handling across all layers:

| Layer | Error Mode | Resilience & Recovery Mechanism |
| :--- | :--- | :--- |
| **Collector** | Malformed / corrupted packet headers | Truncated or non-IP headers are safely skipped without throwing; tracked in `corrupted_packets` counter. |
| **Collector** | Scapy startup failure / permission denied / sniffer thread dies | Reported as mode `failed` with the reason; stale references cleared; never reported as `live`. Simulation only on explicit opt-in. |
| **Collector** | Capture faster than storage | Bounded queue; overflow counted in `packets_dropped`. On stop the queue is drained and open flows are flushed. |
| **File portal** | SOC database unavailable during upload/download | The file operation and its `FileActivity` row still commit; the security event is retried from the outbox (`application_events_pending` in `/health`). |
| **Event Processor** | Alert/device/correlation stage fails after storage | The event row is kept with `processing_status=downstream_error` and `processing_error`. |
| **Collector** | Callback / Ingestion crash | Unhandled exceptions inside packet callbacks are caught; `processing_errors` is incremented; collector thread remains running. |
| **Collector** | Ingestion failures returned as error dicts | Correctly detected and incremented in `processing_errors`; **never** counted as successful `events_ingested`. |
| **PCAP Upload**| Invalid `max_packets` or empty files | Strictly validated before processing; non-integers, `<= 0`, and limits exceeding `MAX_PCAP_PACKETS` return HTTP 400. |
| **Event Processor**| AI model missing or inference failure | **Persist-First Guarantee**: the event is committed *before* the detector runs. `detection_status` is `unavailable`, `unsupported` or `failed`, `anomaly_score=null`, and no alert is created. Never dropped, never given a false zero score. Returns HTTP 202 Accepted. |
| **Database** | Transaction conflicts / commit errors | Atomic operations with explicit `db.session.rollback()` handlers prevent pending transaction lockouts. |
| **Streaming**| SSE client disconnect / network drop | Generator wrapped in `finally: proc.unsubscribe(q)` to prevent memory leaks and orphaned queues. |

---

## 6. Directory Structure

```
d:\invaders 3.0\
├── app.py                      # Flask Application factory & runner
├── config.py                   # Central settings, thresholds, and paths
├── requirements.txt            # Project dependencies
├── demo_pipeline.py            # End-to-end workflow validation script
├── live_collector.py           # Standalone live packet sniffer CLI
├── run_tests.py                # Universal test suite runner
├── pytest.ini                  # Pytest configuration & warning filters
├── pytest.bat / pytest.cmd     # Windows command shims for pytest
├── conftest.py                 # Pytest root path bootstrap
├── README.md                   # Complete architectural and API documentation
│
├── docs/
│   ├── API.md                  # Every registered route: method, role, request/response, errors
│   └── EVENT_PIPELINE.md       # Event envelope, collector, flows, TLS, correlation, detector boundary
│
├── core/
│   ├── database.py             # SQLAlchemy instance
│   ├── migrations.py           # Idempotent schema upgrades for existing databases (keeps rows)
│   ├── models.py               # Event (+envelope), Alert, Device, ModelVersion, AnalystAction, EventCorrelation, User, FileActivity
│   └── models_db.py            # (Legacy prototype models — superseded by models.py)
│
├── extractor/
│   ├── inc_stat.py             # 1D & 2D Damped Incremental Statistics
│   └── afterimage.py           # Kitsune 100-dimensional header feature extractor
│
├── ml/
│   ├── autoencoder.py          # PyTorch-backed bottleneck Autoencoder
│   ├── clustering.py           # Hierarchical correlation-based feature mapper
│   ├── kitnet.py               # Complete KitNET online/offline ensemble detector
│   ├── risk_engine.py          # Dynamic Z-score thresholding & contextual threat heuristics
│   └── explanation_engine.py   # XAI reconstruction error decomposition & SOC narrative
│
├── services/
│   ├── event_processor.py      # Single event boundary: persist → detect → alert → device → correlate → SSE
│   ├── live_collector.py       # Collector state machine, capture queue/worker, PCAP analysis
│   ├── network_metadata.py     # Packet header metadata extraction (no payload retention)
│   ├── flow_aggregator.py      # Bidirectional flow aggregation with timeouts and memory bound
│   ├── tls_metadata.py         # ClientHello/ServerHello fields, SNI, JA3 (no decryption)
│   ├── zeek_tls.py             # Optional Zeek ssl.log enrichment for PCAPs
│   ├── correlation.py          # Conservative application ↔ network correlation
│   ├── app_activity.py         # FileActivity → security event outbox
│   ├── model_adapter.py        # Teammate model verification, calibration, and hot-swapping
│   ├── training_service.py     # BoT-IoT normal data training & ModelVersion recording
│   └── simulation_service.py   # Background live traffic replay routed through EventProcessor
│
├── frontend/                   # VEYLIX React dashboard (SOC + employee portal); see frontend/README.md
│
├── core/auth.py                # Session helpers, SOC role guard, demo account seeding
│
├── api/
│   ├── routes_auth.py          # POST /api/v1/auth/login|logout, GET /api/v1/auth/me
│   ├── routes_files.py         # /api/v1/files (list, upload, download, activity), GET /api/v1/employees/me
│   ├── routes_events.py        # POST /api/v1/events (ingestion), GET event log / stats / detail
│   ├── routes_alerts.py        # GET/PATCH /api/v1/alerts & /alerts/{id} (filters, evidence, audit)
│   ├── routes_devices.py       # GET /api/v1/devices/{id}/timeline, GET /devices, POST flag
│   ├── routes_collector.py     # GET/POST /api/v1/collector (start, stop, status, interfaces, pcap)
│   ├── routes_model.py         # GET/POST /api/v1/model (status, train, thresholds, verify, features)
│   ├── routes_dataset.py       # GET/POST /api/v1/dataset (universal dataset info, upload, schema)
│   ├── routes_metrics.py       # GET /api/v1/metrics (model calibration, system counters, SOC stats)
│   ├── routes_health.py        # GET /api/v1/health (service, db ping, and collector mode)
│   ├── routes_stream.py        # GET /api/v1/stream/live (SSE feed) & simulation controls
│   ├── routes_detection.py     # (Legacy prototype route — superseded by routes_events.py)
│   ├── routes_hosts.py         # (Legacy prototype route — superseded by routes_devices.py)
│   └── routes_stats.py         # (Legacy prototype route — superseded by routes_metrics.py)
│
├── data/
│   ├── dataset_generator.py    # Generates realistic BoT-IoT normal & attack splits
│   ├── botiot_normal_train.csv # Clean benign enterprise traffic for baseline
│   └── botiot_attack_test.csv  # Labeled testing stream with insider exfiltration attacks
│
└── tests/
    ├── test_event_pipeline.py  # Outbox, detector boundary, correlation, collector modes, PCAP, roles, health, SSE, migration
    ├── test_network_metadata.py# Packet metadata, TLS/JA3, flow aggregation, Zeek log parsing
    ├── net_builders.py         # Synthetic packets / TLS handshakes for tests
    ├── test_auth_and_files.py  # Login/session, role isolation, file portal, dashboard contract fields
    ├── test_integration.py     # Person 4 Definition of Done end-to-end integration test suite
    ├── test_collector.py       # Live network collector & metadata extraction tests
    ├── test_errors_and_resilience.py # Error handling, malformed packets, and recovery tests
    ├── test_pcap_validation.py # PCAP input validation, boundary enforcement tests
    ├── test_routes_and_health.py # Canonical route registration, health ping, and metrics tests
    ├── test_model_adapter.py   # Model verification, custom teammate models, hot-swapping tests
    ├── test_api.py             # Route contract tests (health, devices, alerts, simulation)
    ├── test_extractor.py       # Unit tests for AfterImage & incremental stats
    ├── test_kitnet.py          # Unit tests for KitNET, AEs, and feature clustering
    └── test_risk_explanation.py# Unit tests for Risk Engine & XAI narratives
```

---

## 7. REST & SSE API Reference

Full reference with roles and request/response/error schemas: **[docs/API.md](docs/API.md)**.

### Canonical Blueprints Registered in `app.py`:

| Blueprint | Base Path | Key Endpoints | Purpose |
| :--- | :--- | :--- | :--- |
| **`bp_collector`** | `/api/v1/collector` | `GET /status`, `GET /interfaces`, `POST /start`, `POST /stop`, `POST /pcap` | Network capture (POST = ADMIN), interface discovery, PCAP analysis |
| **`bp_events`** | `/api/v1/events` | `POST /` (single & batch), `GET /`, `GET /stats`, `GET /<uuid>` | Network event ingestion; SOC event log with correlations |
| **`bp_alerts`** | `/api/v1/alerts` | `GET /`, `GET /<id>`, `PATCH /<id>` | Alert triage, disposition update, SOC evidence |
| **`bp_devices`** | `/api/v1/devices` | `GET /`, `GET /<id>/timeline`, `POST /<id>/flag` | Workstation profiles, timeline, quarantine toggle |
| **`bp_model`** | `/api/v1/model` | `GET /status`, `POST /verify`, `POST /train`, `POST /thresholds`, `GET /features` | Model inspection, teammate model verification, hot-swapping |
| **`bp_dataset`** | `/api/v1/dataset` | `GET /info`, `GET /sample`, `POST /upload`, `POST /generate` | Universal dataset ingestion (CIC-IDS, UNSW-NB15, Zeek) |
| **`bp_metrics`** | `/api/v1/metrics` | `GET /` | Operational metrics, collector telemetry, precision estimates |
| **`bp_health`** | `/api/v1/health` | `GET /` | Live database ping query, collector mode, model availability |
| **`bp_stream`** | `/api/v1/stream` | `GET /live`, `GET /status`, `POST /start`, `/pause`, `/resume`, `/stop` | Typed SSE feed (SOC only) and dataset replay controls (ADMIN) |
| **`bp_auth`** | `/api/v1/auth` | `POST /login`, `GET /me`, `POST /logout` | Portal sessions (HttpOnly cookie) |
| **`bp_files`** | `/api/v1/files` | `GET /?folder_id=`, `POST /`, `GET /<id>/download`, `GET /activity` | Employee file portal (EMPLOYEE role) |
| **`bp_employees`** | `/api/v1/employees` | `GET /me` | Signed-in user profile and storage usage |

SOC responses also carry the dashboard contract fields defined in `frontend/src/api/schemas.ts`
(`items`, `device_id`, `destination`, `signals`, `risk_contributions`, `events`, `traffic_trend`, …) alongside the
original fields. `PATCH /alerts/{id}` additionally accepts the dashboard vocabulary: `new` → `open`,
`false_positive` → `dismissed` + disposition `false_positive`, and `note` → `analyst_notes`.

> **Note on Unregistered Routes**: `routes_detection.py`, `routes_hosts.py`, and `routes_stats.py` were early prototypes that queried `core/models_db.py`. They are intentionally omitted from registration to prevent route duplication and avoid querying unpopulated tables.

---

## 8. Configuration Variables

Settings in [config.py](file:///d:/invaders%203.0/config.py) configurable via environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `FLASK_DEBUG` | `False` | Enables Flask debug mode (defaults to `False` for production security). |
| `SECRET_KEY` | random, kept in `instance/.secret_key` | Signs the portal session cookie. Set explicitly when running several instances. |
| `DATABASE_URL` | `sqlite:///instance/insider_threat.db` | PostgreSQL connection string or local SQLite fallback. |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated list for restricted environments). |
| `MAX_CONTENT_LENGTH` | `104857600` (100 MB) | Maximum allowable payload size for file uploads. |
| `MAX_PCAP_PACKETS` | `50000` | Upper limit on packet processing for PCAP uploads. |
| `SOC_AUTH_REQUIRED` | `True` | Require a `SECURITY_ANALYST`/`ADMIN` session on SOC routes (and `ADMIN` for service operations). |
| `DETECTOR_BACKEND` | `kitnet_baseline` | `none` disables inference (events stored as `detection_status=unavailable`). |
| `INGEST_API_KEY` | *(empty)* | When set, `POST /api/v1/events` requires `X-Ingest-Key` (or an ADMIN session). |
| `COLLECTOR_ALLOWED_INTERFACES` | *(any)* | Interfaces an operator may capture on. List only networks you are authorised to monitor. |
| `COLLECTOR_PACKET_EVENTS` | `True` | Store one event per packet in addition to flows. |
| `FLOW_IDLE_TIMEOUT_S` / `FLOW_ACTIVE_TIMEOUT_S` / `FLOW_MAX_TRACKED` | `30` / `300` / `10000` | Flow aggregation. |
| `INTERNAL_NETWORKS` | RFC 1918 + CGNAT + loopback/link-local/ULA | Organisation address space for direction and "external" checks. |
| `CORRELATION_WINDOW_S`, `APP_SERVER_PORTS`, `CORRELATION_ADDRESS_PROXIMITY` | `120`, `$PORT`, `True` | Correlation; see docs/EVENT_PIPELINE.md §6. |
| `ZEEK_BIN` | `zeek` | Optional Zeek binary for PCAP TLS enrichment. |
| `SSE_MAX_SUBSCRIBERS` / `SSE_HEARTBEAT_S` | `50` / `15` | Live stream limits. |
| `AUTH_DATABASE_URL` | `sqlite:///instance/veylix_users.db` | Users + employee file portal database. |
| `SEED_DEMO_USERS` | `True` | Create the 20 worker + 2 analyst accounts when the users database is empty. |
| `SESSION_COOKIE_SECURE` | `False` | Set `True` when served over HTTPS. |
| `SESSION_HOURS` | `8` | Session lifetime. |

---

## 9. Verification & Test Suite Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Execute Automated Test Suite (113 backend + 24 frontend tests)
Run any of the following commands in the project directory:

```bash
# Recommended Universal Runner (runs in any environment without PATH dependencies):
python run_tests.py

# Or via Python module:
python -m pytest

# Or directly (supported via pytest.bat / pytest.cmd shims):
pytest
```

Frontend (Vitest + Testing Library): `cd frontend && npm test`.

The test suites build their apps against in-memory databases. Importing `app.py` no longer creates a
production app against `instance/`; the module-level `app` is created lazily on first access.

**Backend test modules:**
- `tests/test_event_pipeline.py` (31 tests): application-activity outbox, idempotency, detector unavailable/disabled/unsupported, MOCKED detector interface, database and downstream failures, correlation (high/ambiguous/shared-address/low), collector live/failed/simulation/concurrency, PCAP, roles, ingestion key, health, SSE auth and cleanup, schema migration.
- `tests/test_network_metadata.py` (17 tests): packet metadata, TLS/JA3 reference vector, GREASE, truncation, flow grouping/timeouts/eviction, Zeek log parsing.
- `tests/test_api.py` (4 tests): Health, device listing & quarantine, stream simulation, alert filtering.
- `tests/test_collector.py` (4 tests): Collector status, interface enumeration, start/stop, 5-tuple extraction.
- `tests/test_errors_and_resilience.py` (9 tests): Corrupted packet handling, callback error isolation, PCAP error recovery, idempotent lifecycle, persist-first guarantee, live capture execution, startup failure stale sniffer cleanup, fallback mode verification, non-double-counting error metrics.
- `tests/test_pcap_validation.py` (7 tests): Missing PCAP file rejection, invalid extensions, empty files, non-integer max_packets, zero/negative limits, excessive packet limits.
- `tests/test_routes_and_health.py` (5 tests): Canonical route registration verification, legacy route exclusion (404), live database ping check, collector mode reporting, metrics consistency.
- `tests/test_extractor.py` (3 tests): 1D & 2D incremental damped statistics, 100-D AfterImage feature vector generation.
- `tests/test_integration.py` (15 tests): End-to-end Definition of Done integration tests, alert updates, device timelines, metrics.
- `tests/test_kitnet.py` (3 tests): Autoencoder forward pass & training, hierarchical correlation clustering, checkpoint persistence.
- `tests/test_model_adapter.py` (4 tests): Active model verification, custom teammate callables, incompatible model rejection, hot-swapping.
- `tests/test_risk_explanation.py` (3 tests): Risk Engine normal/threat evaluation, XAI narrative generation, feature attribution.

### 3. Run End-to-End Pipeline Demo
```bash
python demo_pipeline.py
```

### 4. Start Production Server
```bash
python app.py
```
- Listens on `http://0.0.0.0:5000`.
- Automatically connects to PostgreSQL via `DATABASE_URL` (falls back to SQLite for local development).

---

## 10. Known Limitations

1. **AI model**: the final model is trained by a teammate and is not integrated. The bundled KitNET checkpoint is a
   bootstrap baseline (`final_model: false`). Flow events have no compatible model (`unsupported`). See
   docs/EVENT_PIPELINE.md §7 for the integration boundary.
2. **Live capture** needs a capture provider (Npcap on Windows, libpcap plus `CAP_NET_RAW`/root on Linux). Without one,
   the collector reports `failed` / `live_capture_available: false`; it does not fall back silently.
3. **TLS**: there is no TCP reassembly (split ClientHellos give no JA3), and no JA4. Zeek enrichment applies to PCAP uploads only.
4. **Correlation** is limited to the evidence the portal and collector actually have. Behind a reverse proxy, the
   client address is the proxy's, so nothing is attributed.
5. **Retention**: events are not expired automatically. With `COLLECTOR_PACKET_EVENTS=true`, live capture writes one row per packet.
