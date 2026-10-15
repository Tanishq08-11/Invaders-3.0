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
       |  • Fault-isolated packet sniffer with corrupted frame skip  |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                     EVENT PROCESSOR                         |
       |  • Invariant: PERSIST RAW EVENT FIRST                       |
       |  • Preserves events with ai_error if model degraded         |
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
- **Live Interface Sniffing**: Uses Scapy `AsyncSniffer` to capture raw packets across physical and virtual network adapters.
- **Zero Decryption Guarantee**: Extracts strictly 5-tuple metadata:
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
- **Offline PCAP / PCAPNG Ingestion**: Parses `.pcap`, `.pcapng`, or `.cap` capture files directly into the pipeline without decrypting payloads.
- **Environment Fallback**: Automatically activates a simulated background worker if Npcap/WinPcap or root raw-socket permissions are unavailable in restricted sandboxes or headless CI environments.

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
| **Collector** | Malformed / corrupted packet headers | Truncated or malformed headers are safely discarded without throwing; `corrupted_packets` counter is incremented in telemetry. |
| **Collector** | BPF filter syntax error / permission denied | Scapy exceptions are intercepted; collector logs error details in `last_collector_error` and safely falls back to simulation mode. |
| **Pipeline** | Callback / Ingestion crash | Unhandled exceptions inside packet callbacks are caught; `processing_errors` is incremented; collector thread remains running. |
| **Event Processor**| AI model missing or inference failure | **Persist-First Guarantee**: Raw event is committed to the database *first*. When AI fails, `ai_processed=False`, `anomaly_score=null`, and `ai_error` is saved. Event is **never dropped** or given a false zero score. |
| **Database** | Transaction conflicts / commit errors | Atomic operations with explicit `db.session.rollback()` handlers prevent pending transaction lockouts. |
| **Test Runner** | Missing `pytest` binary in system `PATH` | Shims (`pytest.bat`, `pytest.cmd`, `run_tests.py`) ensure test suite execution succeeds on any Windows/Linux/CI environment. |

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
│   └── models.py               # Models: Event, Alert, Device, ModelVersion, AnalystAction
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
│   ├── routes_health.py        # GET /api/v1/health (service, db, and model availability)
│   └── routes_stream.py        # GET /api/v1/stream/live (SSE feed) & simulation controls
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
    ├── test_model_adapter.py   # Model verification, custom teammate models, hot-swapping tests
    ├── test_api.py             # Route contract tests (health, devices, alerts, simulation)
    ├── test_extractor.py       # Unit tests for AfterImage & incremental stats
    ├── test_kitnet.py          # Unit tests for KitNET, AEs, and feature clustering
    └── test_risk_explanation.py# Unit tests for Risk Engine & XAI narratives
```

---

## 7. REST & SSE API Reference

### 1. Live Network Collector
- `GET /api/v1/collector/status` — Returns sniffer state, packet/byte counts, throughput (pkts/sec), corrupted packets, and error telemetry.
- `GET /api/v1/collector/interfaces` — Lists available network adapters on the host.
- `POST /api/v1/collector/start` — Starts live packet capture (`{"interface": "Wi-Fi", "filter": "ip", "simulate": false}`).
- `POST /api/v1/collector/stop` — Halts packet capture and returns session telemetry.
- `POST /api/v1/collector/pcap` — Multipart upload of raw `.pcap`/`.pcapng` files for automated metadata streaming.

### 2. Ingestion
- `POST /api/v1/events` — Ingest single network flow event.
  - **Design Invariant**: Persist first. Raw event is saved to the database *before* AI scoring.
  - If model fails, saves event with `ai_error` message and returns HTTP 202 Accepted.
  - Supports batch ingestion via `{"events": [...]}`.

### 3. Model Management & Teammate Verification
- `GET /api/v1/model/status` — Inspects active KitNET detector, baseline statistics ($\mu, \sigma, \max$), and cluster layouts.
- `POST /api/v1/model/verify` — Validates candidate models against 100-D input specification, benchmarks inference latency, and supports dynamic hot-swapping (`{"deploy": true}`).
- `POST /api/v1/model/train` — Retrains KitNET baseline on clean traffic dataset.
- `POST /api/v1/model/thresholds` — Dynamically updates Z-score severity thresholds (`z_low`, `z_med`, `z_high`, `z_crit`).
- `GET /api/v1/model/features` — Lists the 100 AfterImage features with descriptions and cluster assignments.

### 4. Alert Triage Lifecycle
- `GET /api/v1/alerts` — Query parameters: `severity`, `status`, `device_id`, `limit`, `offset`.
- `GET /api/v1/alerts/<id_or_uuid>` — Retrieves full alert with top-5 feature error attributions, SOC narrative, and mitigation playbook.
- `PATCH /api/v1/alerts/<id_or_uuid>` — Updates alert disposition (`threat_confirmed`, `benign_activity`, `policy_violation`, `false_positive`), status, and analyst notes.

### 5. Device Timeline & Quarantine
- `GET /api/v1/devices` — Lists all tracked internal workstations ranked by risk score and alert count.
- `GET /api/v1/devices/<id>/timeline` — Returns endpoint event history and linked security incidents.
- `POST /api/v1/devices/<id>/flag` — Toggles workstation quarantine status.

### 6. System Metrics & Health
- `GET /api/v1/metrics` — Ingestion counts, model calibration parameters, precision estimates, and severity distribution.
- `GET /api/v1/health` — Readiness status (`healthy` or `degraded`), database connection, and model loading state.

### 7. Real-Time Streaming (SSE)
- `GET /api/v1/stream/live` — Server-Sent Events stream delivering live telemetry and alerts to dashboard clients.
- `POST /api/v1/stream/start`, `/pause`, `/resume`, `/stop` — Controls simulated traffic replay.

---

## 8. Verification & Test Suite Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Execute Automated Test Suite (42/42 Tests)
Run any of the following commands in the project directory:

```bash
# Recommended Universal Runner (runs in any environment without PATH dependencies):
python run_tests.py

# Or via Python module:
python -m pytest

# Or directly (supported via pytest.bat / pytest.cmd shims):
pytest
```

**Test Suite Coverage (42 Total Tests):**
- `tests/test_api.py` (4 tests): Health, device listing & quarantine, stream simulation, alert filtering.
- `tests/test_collector.py` (4 tests): Collector status, interface enumeration, start/stop, 5-tuple extraction.
- `tests/test_errors_and_resilience.py` (6 tests): Corrupted packet handling, callback error isolation, PCAP error recovery, idempotent lifecycle, persist-first guarantee, live capture execution.
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
