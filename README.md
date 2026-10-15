# AI Insider Threat Detection System: Encrypted Traffic Analysis

An enterprise-grade, AI-powered cybersecurity backend that detects rogue insiders exfiltrating sensitive corporate data by analyzing **encrypted network traffic without decrypting its contents**.

Powered by **Live Network Metadata Sniffing**, **Kitsune's AfterImage Feature Extractor**, an **Ensemble of Autoencoders (KitNET)**, a **Teammate Model Verification & Hot-Swapping Adapter**, a contextual **Risk Engine**, an **Explainable AI (XAI) Engine**, and a high-performance **Flask REST & SSE Streaming Backend** built for Security Operations Center (SOC) dashboards.

---

## 1. Architectural Workflow

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
- **Explicit Operating Modes**:
  - `live`: Scapy `AsyncSniffer` actively capturing raw packets on host network adapters.
  - `simulation`: Background simulated traffic worker emitting synthetic flows for development/hackathon environments where raw socket privileges are restricted.
  - `stopped`: Collector is halted.
- **Zero Decryption Guarantee**: Extracts strictly 5-tuple metadata without ever decrypting or inspecting packet payloads:
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
- **Environment Fallback**: If Scapy startup fails (e.g. Npcap missing or raw-socket privilege denied), the collector records the failure, clears stale sniffer references, and safely switches to simulation mode without falsely reporting live capture.

### Command-Line Usage
```bash
# List available network interfaces on the host
python live_collector.py --list-interfaces

# Start live packet capture on a specific adapter with BPF filter
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
| **Collector** | Scapy startup failure / permission denied | Scapy exceptions are recorded; stale references are cleared; collector safely switches to simulation mode explicitly. |
| **Collector** | Callback / Ingestion crash | Unhandled exceptions inside packet callbacks are caught; `processing_errors` is incremented; collector thread remains running. |
| **Collector** | Ingestion failures returned as error dicts | Correctly detected and incremented in `processing_errors`; **never** counted as successful `events_ingested`. |
| **PCAP Upload**| Invalid `max_packets` or empty files | Strictly validated before processing; non-integers, `<= 0`, and limits exceeding `MAX_PCAP_PACKETS` return HTTP 400. |
| **Event Processor**| AI model missing or inference failure | **Persist-First Guarantee**: Raw event is committed to the database *first*. When AI fails, `ai_processed=False`, `anomaly_score=null`, and `ai_error` is saved. Event is **never dropped** or given a false zero score. Returns HTTP 202 Accepted. |
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
├── core/
│   ├── database.py             # SQLAlchemy instance
│   ├── models.py               # Canonical Models: Event, Alert, Device, ModelVersion, AnalystAction
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
│   ├── event_processor.py      # Persist-first ingestion, scoring, alert creation, SSE broadcasting
│   ├── live_collector.py       # Live Scapy packet sniffer, PCAP streamer, error telemetry
│   ├── model_adapter.py        # Teammate model verification, calibration, and hot-swapping
│   ├── training_service.py     # BoT-IoT normal data training & ModelVersion recording
│   └── simulation_service.py   # Background live traffic replay routed through EventProcessor
│
├── api/
│   ├── routes_events.py        # POST /api/v1/events (single & batch ingestion)
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

### Canonical Blueprints Registered in `app.py`:

| Blueprint | Base Path | Key Endpoints | Purpose |
| :--- | :--- | :--- | :--- |
| **`bp_collector`** | `/api/v1/collector` | `GET /status`, `GET /interfaces`, `POST /start`, `POST /stop`, `POST /pcap` | Live network packet capture, interface discovery, PCAP upload |
| **`bp_events`** | `/api/v1/events` | `POST /` (single & batch) | Persist-first network event ingestion |
| **`bp_alerts`** | `/api/v1/alerts` | `GET /`, `GET /<id>`, `PATCH /<id>` | Alert triage, disposition update, SOC evidence |
| **`bp_devices`** | `/api/v1/devices` | `GET /`, `GET /<id>/timeline`, `POST /<id>/flag` | Workstation profiles, timeline, quarantine toggle |
| **`bp_model`** | `/api/v1/model` | `GET /status`, `POST /verify`, `POST /train`, `POST /thresholds`, `GET /features` | Model inspection, teammate model verification, hot-swapping |
| **`bp_dataset`** | `/api/v1/dataset` | `GET /info`, `POST /upload`, `POST /convert` | Universal dataset ingestion (CIC-IDS, UNSW-NB15, Zeek) |
| **`bp_metrics`** | `/api/v1/metrics` | `GET /` | Operational metrics, collector telemetry, precision estimates |
| **`bp_health`** | `/api/v1/health` | `GET /` | Live database ping query, collector mode, model availability |
| **`bp_stream`** | `/api/v1/stream` | `GET /live`, `POST /start`, `/pause`, `/resume`, `/stop` | Server-Sent Events (SSE) feed and simulation replay |

> **Note on Unregistered Routes**: `routes_detection.py`, `routes_hosts.py`, and `routes_stats.py` were early prototypes that queried `core/models_db.py`. They are intentionally omitted from registration to prevent route duplication and avoid querying unpopulated tables.

---

## 8. Configuration Variables

Settings in [config.py](file:///d:/invaders%203.0/config.py) configurable via environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `FLASK_DEBUG` | `False` | Enables Flask debug mode (defaults to `False` for production security). |
| `SECRET_KEY` | `insider-threat-ai-secret-key-2026` | Flask cryptographic session key. |
| `DATABASE_URL` | `sqlite:///instance/insider_threat.db` | PostgreSQL connection string or local SQLite fallback. |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated list for restricted environments). |
| `MAX_CONTENT_LENGTH` | `104857600` (100 MB) | Maximum allowable payload size for file uploads. |
| `MAX_PCAP_PACKETS` | `50000` | Upper limit on packet processing for PCAP uploads. |

---

## 9. Verification & Test Suite Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Execute Automated Test Suite (57/57 Tests)
Run any of the following commands in the project directory:

```bash
# Recommended Universal Runner (runs in any environment without PATH dependencies):
python run_tests.py

# Or via Python module:
python -m pytest

# Or directly (supported via pytest.bat / pytest.cmd shims):
pytest
```

**Complete Test Suite Breakdown (57 Total Tests Across 10 Test Modules):**
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

1. **AI Model Integration**: The trained AI model is developed by a teammate; the backend is currently configured with the baseline model adapter and verification seam awaiting the teammate's final model checkpoint.
2. **Raw Packet Capture Permissions**: Raw packet capture via Scapy requires OS-level packet capture drivers (WinPcap/Npcap on Windows, `CAP_NET_RAW` / root on Linux). In sandboxed or unprivileged CI environments, the collector gracefully runs in simulation mode.
3. **Hackathon Prototype Authentication**: User authentication and API token validation are intentionally omitted in this hackathon prototype to allow seamless dashboard demonstration and integration testing.
