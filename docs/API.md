# API reference (`/api/v1`)

This table matches the routes registered in `app.py` (40 routes; generated from `app.url_map`).
Every response is JSON. Errors use `{"detail": "…"}` (auth, files, HTTP errors) or `{"error": "…"}`
(pipeline routes). The frontend reads either field and shows it to the user. Clients never receive stack
traces, filesystem paths or storage keys.

## Roles

| Role | Can do |
|---|---|
| anonymous | `GET /health` (minimal fields), `POST /auth/login`, `POST /events` when `INGEST_API_KEY` is unset |
| `EMPLOYEE` | File portal (`/files`, `/employees/me`) |
| `SECURITY_ANALYST` | All SOC reads (alerts, events, devices, metrics, collector status, SSE), alert triage (`PATCH /alerts/{id}`), device flagging |
| `ADMIN` | Everything an analyst can, plus every non-GET request under `/collector`, `/stream`, `/model`, `/dataset` (collector start/stop, PCAP analysis, dataset replay, model management) |

Enforcement lives in `core/auth.py` (`install_soc_guard` by URL prefix, `role_required` per route). The
backend derives identity from the session cookie only; a `user_id` (or `source`, `device_id`,
`event_type=application_activity`) sent by a client is ignored or rejected. `SOC_AUTH_REQUIRED=false`
turns the SOC role checks off for local development and the legacy test suites. The ingestion key check
stays on whenever `INGEST_API_KEY` is set.

## Event types

| `event_type` | Produced by | Model input? | Notes |
|---|---|---|---|
| `application_activity` | The portal itself (`/files` upload, download, denied/failed operations) | Never (`detection_status=not_applicable`) | Authenticated `user_id`, `action`, `outcome`, client address seen by the portal (`src_ip`), file id/size/type/location. No file names, contents or paths. |
| `network_packet` | Live capture, PCAP, simulation | Yes, with the existing AfterImage→KitNET detector | One row per observed packet when `COLLECTOR_PACKET_EVENTS=true`. Linked to its flow by `flow_id`. Not streamed over SSE. |
| `network_flow` | Flow aggregator (live, PCAP, simulation) | No compatible model yet (`unsupported`) | Completed bidirectional flow: counts, bytes, size/IAT statistics, TCP flags and TLS handshake metadata in `details`. |
| `network_record` | `POST /events`, BoT-IoT dataset replay | Yes | Externally supplied flow records (the original ingestion contract). |

`source` is one of `live_capture`, `pcap`, `simulation`, `dataset_replay`, `api`, `application`, or `legacy`
(rows stored before this change). The dashboard maps it to `data_source`: `live` | `simulation` | `replay` | `pcap` | `unknown`.

`detection_status` is one of `scored`, `unavailable` (no model loaded, or the detector is disabled), `unsupported`,
`failed`, `pending`, or `not_applicable`. `anomaly_score` is `null` unless the status is `scored`. Alerts are only created from a
`scored` result.

`processing_status` is `stored`, then either `complete` or `downstream_error`. A downstream error means the alert,
device or correlation stage failed after the event was stored; the event is kept and `processing_error` holds the reason.

## Routes

### Auth and portal

| Method | Route | Role | Request | Success | Errors |
|---|---|---|---|---|---|
| POST | `/auth/login` | – | `{username, password}` | `200 {user}` + HttpOnly session cookie | 400 missing fields, 401 bad credentials |
| GET | `/auth/me` | any session | – | `200 User` | 401 |
| POST | `/auth/logout` | – | – | `200 {message}` | – |
| GET | `/employees/me` | any session | – | `200 User` (+ storage usage for employees) | 401 |
| GET | `/files?folder_id=` | EMPLOYEE | – | `200 {items: FileItem[], path, permissions}` | 401, 403 folder of another department, 404 |
| POST | `/files` | EMPLOYEE | multipart `file`, optional `folder_id` | `201 FileItem` | 400 no file, 403, 404, 413 quota or `MAX_CONTENT_LENGTH`, 500 storage error |
| GET | `/files/{id}/download` | EMPLOYEE | – | `200` attachment (`application/octet-stream`) | 403, 404 |
| GET | `/files/activity` | EMPLOYEE | – | `200 {items: [{id, timestamp, action, file_name, result, detail}]}` (own rows only) | 401, 403 |

Every file operation writes one `FileActivity` row and one `application_activity` event (see `docs/EVENT_PIPELINE.md`, outbox).

### Event ingestion and event log

| Method | Route | Role | Request | Success | Errors |
|---|---|---|---|---|---|
| POST | `/events` | open, or `X-Ingest-Key` / ADMIN when `INGEST_API_KEY` is set | Single event `{src_ip, dst_ip?, src_port?, dst_port?, protocol?, bytes?, pkts?, duration?, timestamp?, event_type?, event_id?}` (BoT-IoT/CIC/Zeek aliases accepted), or `{events: [...]}` (max 500) | `201` when scored, `202` when stored without a score. Body: the stored event, plus `alert`, `risk_eval`, `explanation`, and `_warning` when detection was unavailable or failed. A batch returns `201 {total_processed, stored, threats_detected, errors, results}`. Re-sending an `event_id` returns the stored event with `duplicate: true`. | 400 invalid JSON, invalid IP or disallowed `event_type`; 401 missing or wrong ingest key; 413 batch too large; 503 database write failed |
| GET | `/events` | SOC | Query: `type` (comma list), `source`, `detection_status`, `user_id`, `src_ip`, `flow_id`, `since` (ISO-8601), `before_id`, `limit` (≤500, default 100) | `200 {items: Event[], next_before_id}`, newest first. Application events include `user: {username, display_name, department}`. | 400 bad parameter |
| GET | `/events/stats` | SOC | – | `200 {by_type, by_source, by_detection_status, correlations, processor}` | – |
| GET | `/events/{event_uuid}` | SOC | – | `200 Event` + `details`, `correlations[]` (each with `method`, `confidence`, `time_delta_s`, `rationale`, `related_event`), `packet_event_count` (flows), `flow_event_uuid` (packets), `alert` | 404 |

`Event` fields: `id, event_uuid, event_type, source, data_source, timestamp, received_at, processing_status,
processing_error, detection_status, user_id, action, outcome, flow_id, direction, device_id, src_ip, dst_ip,
src_port, dst_port, protocol, bytes_transferred, packet_count, flow_duration, bytes_out, bytes_in, packets_out,
packets_in, duration_seconds, tls_sni, anomaly_score, ai_processed, ai_error, alert_id`.

### Network collector

| Method | Route | Role | Request | Success | Errors |
|---|---|---|---|---|---|
| GET | `/collector/status` | SOC | – | `200 CollectorStatus` (below) | – |
| GET | `/collector/interfaces` | SOC | – | `200 {total, interfaces: [{name, description, ips[], allowed}], live_capture_available, live_capture_unavailable_reason}` | – |
| POST | `/collector/start` | ADMIN | `{mode: "live" \| "simulation", interface (required for live), filter? (BPF, restricted charset), allow_simulation_fallback?: false}` (legacy `simulate: true` still works) | `200 {status: started \| already_running, mode, interface, filter}`. Fallback adds `warning` and `mode: simulation`. | 400 missing/unknown/unauthorised interface or bad filter; 409 another start/stop is in progress; 503 capture unavailable or failed to start (`mode: failed`, `error`) |
| POST | `/collector/stop` | ADMIN | – | `200 {status: stopped, previous_mode, packets_captured, events_ingested, flows_completed, duration_s, errors[]}` or `{status: not_running}` (also clears a `failed` state and flushes its open flows) | – |
| POST | `/collector/pcap` | ADMIN | multipart `file` (.pcap/.pcapng/.cap), `max_packets?` (≤ `MAX_PCAP_PACKETS`), `auto_ingest?` | `200 {status: completed, total_packets, packets_parsed, malformed_packets, packet_events, flow_events, flows, events_ingested, threats_detected, processing_errors, tls_handshakes, zeek, sample_metadata}` | 400 missing/empty/wrong extension/not a pcap header/bad `max_packets`; 422 parse error part-way (body carries partial counts; flows read so far are stored); 500 |

`CollectorStatus`: `mode` (`stopped`, `starting`, `live`, `simulation` or `failed`), `is_running`, `is_live`,
`is_simulated`, `source`, `active_interface`, `bpf_filter`, `packets_captured`, `bytes_captured`,
`packets_dropped`, `events_ingested`, `packet_events_ingested`, `flow_events_ingested`, `flows_completed`,
`active_flows`, `queue_depth`, `corrupted_packets`, `collector_errors`, `processing_errors`,
`last_collector_error`, `last_processing_error`, `uptime_seconds`, `throughput_pps`, `live_capture_available`,
`live_capture_unavailable_reason`, `live_capture_verified`, `allowed_interfaces`, `flow_config`,
`tls{builtin_handshake_parser, sni, ja3, ja4, zeek}`, `last_pcap`. All counters describe the current or most recent run.

### Live stream and dataset replay

| Method | Route | Role | Notes |
|---|---|---|---|
| GET | `/stream/live` | SOC | `text/event-stream`. Each message is `id: <n>` followed by `data: {"id", "type", "ts", "data"}`. Types: `hello` (collector and detector snapshot), `event` (flow, record or application event summary), `alert`, `correlation`, and `collector_status` (about every 2 s while running). Heartbeat comment every `SSE_HEARTBEAT_S`. Returns 503 when `SSE_MAX_SUBSCRIBERS` is reached; the client then polls instead. |
| POST | `/stream/start` | ADMIN | Replay `data/botiot_attack_test.csv` as `network_record` events with `source=dataset_replay`. Body `{scenario?, speed_fps?}`. |
| POST | `/stream/pause`, `/stream/resume`, `/stream/stop` | ADMIN | Replay controls |
| GET | `/stream/status` | SOC | Replay status |

### SOC reads and triage (unchanged contracts)

| Method | Route | Role | Notes |
|---|---|---|---|
| GET | `/alerts` | SOC | Filters `severity`, `status`, `src_ip`; `page`, `per_page` (≤1000), `sort`, `order`. Items now include `source` and `data_source`. |
| GET | `/alerts/{id or alert_uuid}` | SOC | Evidence, narrative, mitigation, source events, analyst actions |
| PATCH | `/alerts/{id}` | SOC | `{status?, disposition?, analyst_notes? \| note?}`. Aliases: `new` becomes `open`; `false_positive` becomes `dismissed` with disposition `false_positive`. Audited in `analyst_actions`. |
| GET | `/devices` | SOC | Ranked device profiles |
| GET | `/devices/{id}/timeline` | SOC | Flows and records from that source address only. Packets are excluded because they are already counted in their flow; application events are excluded because they are attributed to users. |
| POST | `/devices/{id}/flag` | SOC | `{is_flagged?}` |
| GET | `/metrics` | SOC | `system` (processor counters), `database` (`events_by_type`, `events_by_detection_status`), `collector`, `model`, `detector`, `evaluation`, `severity_distribution`. `observed_events` and `traffic_trend` count flows and records only. |
| GET | `/health` | public (minimal) / SOC (full) | See below |
| GET | `/model/status`, `/model/features` | SOC | Existing model inspection |
| POST | `/model/train`, `/model/thresholds`, `/model/verify` | ADMIN | Existing model management (unchanged behaviour) |
| GET | `/dataset/info`, `/dataset/sample` | SOC | Existing |
| POST | `/dataset/upload`, `/dataset/generate` | ADMIN | Existing |

### `GET /health`

Anonymous callers get: `status` (`healthy`, `degraded` or `unhealthy`), `service`, `version`, `database`,
`model_loaded`, `detector_state`, and `components{database, detector, model, collector}`.

SOC callers also get:
- `detector`: `state` (`ready`, `unavailable` or `disabled`), `available`, `backend`, `model`, `final_model: false`, `description`, `input_schema`, `accepted_event_types`, `reason`
- `collector`: mode, live-capture availability on this host, `live_capture_verified`, and counters
- `components.live_capture`: `unavailable`, `not_started` or `verified`
- `tls`: built-in parser, JA3, `ja4: unsupported`, Zeek availability
- `sse.subscribers`
- `ingestion_auth`: `open` or `api_key`
- `application_events_pending`: the outbox backlog
- `counters`, `model_info`, `last_event_at`, `data_source`

`status` is `healthy` only when the database answers **and** a detector is loaded. "Flask is running" never counts as AI availability.

## Removed or unregistered

`api/routes_detection.py`, `routes_hosts.py` and `routes_stats.py` are legacy prototypes on `core/models_db.py`. They stay unregistered (`tests/test_routes_and_health.py` asserts that they return 404). `services/detection_service.py` belongs to the same prototype and is not used by the application.
