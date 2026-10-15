# AI Insider Threat Detection System: Encrypted Traffic Analysis

An AI-powered cybersecurity backend that detects rogue insiders leaking sensitive corporate data by analyzing **encrypted network traffic without decrypting its contents**. 

Powered by **Kitsune's AfterImage Feature Extractor**, an **Ensemble of Autoencoders (KitNET)**, a contextual **Alert/Risk Engine**, an **Explainable AI (XAI) Engine**, and a high-performance **Flask REST & SSE Streaming Backend** built for Security Dashboards.

---

## 1. End-to-End Architectural Workflow

```
                        BoT-IoT DATASET
                              |
               +--------------+--------------+
               |                             |
               v                             v
         NORMAL TRAFFIC                ATTACK TRAFFIC
               |                             |
               v                             v
        Training Dataset               Testing Dataset
               |                             |
               v                             |
        Kitsune Feature                      |
     Extractor (AfterImage)                  |
               |                             |
               v                             |
        KitNET Training                      |
        - Feature mapping                    |
        - Autoencoder training               |
               |                             |
               v                             |
     Learned Normal Baseline                 |
               |                             |
               +--------------+--------------+
                              |
                              v
                      INCOMING TRAFFIC
                              |
                              v
                  Kitsune Feature Extractor
                              |
                              v
                       KitNET Detector
                              |
                              v
                        Anomaly Score
                              |
                              v
                     ALERT / RISK ENGINE
                              |
                              v
                      EXPLANATION ENGINE
                              |
                              v
                        FLASK BACKEND
                              |
                              v
                      SECURITY DASHBOARD
```

---

## 2. Core Concepts: Why Encrypted Traffic Analysis Without Decryption?

- **Privacy & Compliance**: Inspecting payload bytes breaks GDPR, HIPAA, and employee confidentiality. Moreover, modern TLS 1.3, Encrypted Client Hello (ECH), and pinned certificates make deep payload inspection impractical or impossible.
- **Header & Behavioral Dynamics**: When an insider exfiltrates databases or confidential IP, the network behavior shifts drastically:
  - High burst velocity and sustained outbound throughput over short time windows ($\lambda = 5.0, 3.0$).
  - MTU frame uniformity (continuous 1400–1500 byte payloads).
  - Outbound-to-inbound asymmetry (heavy upload vs. few ACK packets).
  - Low inter-arrival jitter indicative of automated exfiltration scripts.
- **AfterImage O(1) Damped Statistics**: Computes 100 rolling statistical features across multiple decay windows ($\lambda \in [5, 3, 1, 0.1, 0.01]$) covering 100ms micro-bursts to 1-minute macro trends.
- **KitNET Ensemble of Autoencoders**: Uses hierarchical correlation clustering to partition 100 features into small subsets ($m \le 10$), training an ensemble of compact autoencoders plus an aggregator autoencoder.

---

## 3. Project Directory Structure

```
d:\invaders 3.0\
├── app.py                      # Flask Application factory & runner
├── config.py                   # Central settings, thresholds, and paths
├── requirements.txt            # Project dependencies
├── demo_pipeline.py            # End-to-end workflow validation script
├── README.md                   # Complete architectural and API documentation
│
├── core/
│   ├── database.py             # SQLAlchemy instance
│   └── models.py               # Person 4 Models: Event, Alert, Device, ModelVersion, AnalystAction
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
│   ├── event_processor.py      # Person 4 Integration Seam: persist-first, AI scoring, alert creation, pub/sub
│   ├── training_service.py     # BoT-IoT normal data training & ModelVersion recording
│   └── simulation_service.py   # Background live traffic replay routed through EventProcessor
│
├── api/
│   ├── routes_events.py        # POST /api/v1/events (single & batch ingestion)
│   ├── routes_alerts.py        # GET/PATCH /api/v1/alerts & /alerts/{id} (filters, evidence, audit)
│   ├── routes_devices.py       # GET /api/v1/devices/{id}/timeline, GET /devices, POST flag
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
    ├── test_api.py             # Route contract tests (health, devices, alerts, simulation)
    ├── test_extractor.py       # Unit tests for AfterImage & incremental stats
    ├── test_kitnet.py          # Unit tests for KitNET, AEs, and feature clustering
    └── test_risk_explanation.py# Unit tests for Risk Engine & XAI narratives
```

---

## 4. Person 4 REST API Specification

### 1. Ingestion: Single Event or Batch
- `POST /api/v1/events`
  - **Design Rule**: Persist first. The raw network event is saved to the `events` table *before* the AI touches it.
  - If the AI fails or is unavailable, the event is saved anyway with an explicit `ai_error` message and `anomaly_score: null`. It is **never** dropped or assigned a zero score.
  - Accepts single flow or batch `{"events": [...]}`:
  ```json
  {
    "src_ip": "192.168.1.105",
    "dst_ip": "45.33.32.156",
    "src_port": 55120,
    "dst_port": 443,
    "protocol": "TCP",
    "bytes": 1460,
    "duration": 0.05,
    "timestamp": 1770984000.0
  }
  ```

### 2. Alert Management & Triage Lifecycle
- `GET /api/v1/alerts`
  - Query parameters: `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `status` (`open`, `investigating`, `resolved`, `false_positive`), `device_id`, `limit`, `offset`.
- `GET /api/v1/alerts/<id_or_uuid>`
  - Retrieves full alert incident with linked event record, top 5 feature error attributions, SOC narrative, playbook steps, and full analyst audit log.
- `PATCH /api/v1/alerts/<id_or_uuid>`
  - Updates alert disposition (`threat_confirmed`, `benign_activity`, `policy_violation`, `false_positive`), status, and analyst notes.
  - Records an immutable record in `analyst_actions` for full forensic traceability.

### 3. Device Timeline & Quarantine
- `GET /api/v1/devices/<device_id>/timeline`
  - Returns internal workstation profile, chronological event timeline, and linked alerts.
- `GET /api/v1/devices`
  - Lists all tracked internal endpoints ranked by risk score and alert count. Supports `?flagged_only=true`.
- `POST /api/v1/devices/<device_id>/flag`
  - Toggles host quarantine status.

### 4. Evaluation Metrics
- `GET /api/v1/metrics`
  - Model and system evaluation metrics:
    - **System counters**: events ingested, evaluated, failed, alerts created, active SSE listeners.
    - **Model calibration**: active model version, baseline mean/std/max RMSE, cluster count.
    - **Analyst feedback / evaluation**: verified true positives, false positives, analyst precision estimate.
    - **Severity distribution**: count and percentage breakdown across severities.

### 5. Health & Readiness Check
- `GET /api/v1/health`
  - Reports service status (`healthy` or `degraded`), database connection state, model loading state, and registered routes.

### 6. Real-Time Streaming (SSE)
- `GET /api/v1/stream/live`
  - Server-Sent Events stream emitting live detection telemetry and alerts to dashboard clients.
- `POST /api/v1/stream/start`, `/pause`, `/resume`, `/stop`, `GET /stream/status`
  - Controls replay of the BoT-IoT test dataset through the pipeline.

---

## 5. Quickstart & Verification

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the End-to-End Verification Pipeline
```bash
python demo_pipeline.py
```

### 3. Run the Complete Automated Test Suite (28/28 Tests)
```bash
python -m pytest tests/ -v
```

### 4. Start the Production Backend
```bash
python app.py
```
- Supports PostgreSQL via `DATABASE_URL` environment variable (e.g. `postgresql://user:pass@localhost:5432/threat_db`).
- Falls back automatically to SQLite for local development.
