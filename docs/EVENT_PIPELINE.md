# Event pipeline

This document describes how events move through the system: collection, metadata extraction, flow
aggregation, storage, correlation, detection, alerts and the dashboard. Each stage records its own outcome,
so you can always tell which stage ran and which did not.

```
 Portal file operation (authenticated)          Authorised network traffic / PCAP / simulator
            │                                                   │
   api/routes_files.py                           services/live_collector.py
   FileActivity row (users DB) ─ outbox ─┐       Scapy sniffer callback → bounded queue → worker
            │                            │                      │
            │                            │       services/network_metadata.py  (headers only)
            │                            │       services/tls_metadata.py      (ClientHello/ServerHello fields)
            │                            │                      │
            │                            │       services/flow_aggregator.py   (bidirectional flows)
            │                            │                      │
            ▼                            ▼          network_packet ─┬─ network_flow
   application_activity ──────► services/event_processor.py  ◄─────┘   (+ network_record from POST /events, replay)
                                 1 validate / normalise
                                 2 PERSIST (commit)                  → processing_status = stored
                                 3 detector, if it accepts the type  → detection_status
                                 4 alert, only from a real score
                                 5 device profile
                                 6 correlation (application events & flows) → services/correlation.py
                                 7 SSE broadcast                     → /api/v1/stream/live
                                                │
                     events · event_correlations · alerts · devices  (SOC database)
                                                │
                     REST (/events, /alerts, /collector, /health …) + SSE → React dashboard
```

## 1. Event envelope

All events share the `events` table (`core/models.py`). Envelope columns:

| Column | Meaning |
|---|---|
| `event_uuid` | Unique id (`EVT-…`) |
| `event_type` | `application_activity`, `network_packet`, `network_flow`, `network_record` |
| `source` | `live_capture`, `pcap`, `simulation`, `dataset_replay`, `api`, `application`, `legacy` |
| `event_time` / `received_at` | Observation time (UTC) / storage time |
| `dedup_key` | Idempotency key (`file_activity:<id>`, `flow:<flow_id>`, `api:<event_id>`); unique index |
| `processing_status`, `processing_error` | `stored`, then `complete` or `downstream_error` |
| `detection_status`, `ai_error`, `anomaly_score` | Detector outcome; `anomaly_score` is null unless `scored` |
| `user_id`, `device_id` | Set only when reliably known: the session user for application events; never inferred from an IP |
| `action`, `outcome` | Application events |
| `flow_id`, `direction` | Network linkage; `direction` is `outbound`, `inbound`, `internal` or `external` relative to `INTERNAL_NETWORKS` |
| `src_ip … flow_duration` | Network 5-tuple and volume (nullable for application events) |
| `details_json` | Type-specific metadata (below) |

### Canonical formats (`details`)

**network_packet**: `tcp_flags` (e.g. `"SA"`), `payload_bytes` (size only), `ip_version`, and `tls` when
the segment starts a ClientHello or ServerHello.

**network_flow**: `start_time`, `end_time`, `end_reason` (`idle_timeout`, `active_timeout`, `tcp_close`,
`evicted`, `collector_stopped` or `pcap_end`), `initiator_inferred`, `total_packets`, `fwd_packets`, `bwd_packets`,
`total_bytes`, `fwd_bytes`, `bwd_bytes`, `packet_size{min,max,mean,std}`, `inter_arrival_s{min,max,mean,std}`,
`tcp_flags{syn,ack,fin,rst,psh,urg}` (null for non-TCP), and `tls{sni, ja3, ja3_string, client_offered_versions,
client_alpn, server_negotiated_version, server_cipher_suite, …, extraction_source}`.
Fields that were not observed are null rather than estimated. For example, a one-packet flow has null inter-arrival statistics.

**application_activity**: `file_activity_id`, `file_id`, `kind`, `size_bytes`, `mime_type`, `location`
(`personal` or `department_shared`), `department`, and `correlation{status, app_server_candidates, links,
evaluated_at}`. File names, contents and storage paths are never included.

This canonical flow format is independent of any model's input schema. See section 6.

## 2. Application activity (outbox)

`FileActivity` (users DB) and `events` (SOC DB) are separate databases and cannot share a transaction:

1. The stored file and its `FileActivity` row commit together, with `security_event_status = "pending"` and a
   small payload (client address and file context).
2. `EventProcessor.record_application_activity()` stores the `application_activity` event, deduplicated by
   `file_activity:<id>`.
3. The activity row becomes `recorded` (with `security_event_uuid`) or `failed`.
4. `pending` and `failed` rows are retried after later activity and at startup (`services/app_activity.py`).
   `/health` reports the backlog as `application_events_pending`.

The employee's own activity log never depends on the SOC database being available. A failed upload is never
reported as a success, and denied and failed operations are recorded too.

The portal sees the client address as `request.remote_addr`. No proxy handling is configured, so behind a
reverse proxy this would be the proxy's address. Correlation then refuses to attribute it, because several
users share it (see section 5).

## 3. Network collection

`services/live_collector.py`:

| Mode | Meaning |
|---|---|
| `stopped` | Idle |
| `starting` | Sniffer launched; waiting for Scapy's `started_callback`, which fires only once the capture socket is open |
| `live` | The socket opened. Only now is "live" reported, and `live_capture_verified` becomes true |
| `simulation` | Synthetic packets. Every event has `source=simulation` and the UI shows a SIMULATION banner |
| `failed` | Start failed, or the sniffer thread died mid-run (checked every second). `last_collector_error` says why |

Rules:
- Live capture needs an ADMIN, an interface chosen explicitly from `/collector/interfaces`, and an interface on
  `COLLECTOR_ALLOWED_INTERFACES` when that list is set. Nothing starts at login or at server start.
- The host precheck reports when no capture provider exists (for example Npcap missing on Windows).
- Falling back to simulation only happens with `allow_simulation_fallback: true`, and is then reported with a warning.
- Start and stop are serialised; a concurrent request gets 409 `busy`, and a second start returns `already_running`.
- The sniffer callback only extracts metadata and enqueues it. The queue holds `COLLECTOR_QUEUE_SIZE` items;
  overflow is counted in `packets_dropped`, never silently lost. One worker, running inside the Flask app context, does the processing.
- On stop: the sniffer stops, threads join (with a timeout that is reported), queued packets are processed, and every open flow is flushed (`collector_stopped`).
- Counters describe outcomes. `events_ingested` counts stored rows only; failures go to `processing_errors`.

PCAP (`POST /collector/pcap`) follows the same metadata → flow → processor path with `source=pcap`. The file
header magic is validated first. A separate aggregator uses packet timestamps as its clock, and all flows are
flushed at `pcap_end`. Uploads are written under a random name and deleted afterwards.

## 4. Flow aggregation

`services/flow_aggregator.py` uses the canonical key `(protocol, lower endpoint, higher endpoint)`, so both
directions map to the same flow. The initiator is the sender of a bare SYN; otherwise it is the first sender seen, and the flow is marked
`initiator_inferred: true`. Timeouts: `FLOW_IDLE_TIMEOUT_S` (30), `FLOW_ACTIVE_TIMEOUT_S` (300), plus TCP close
(FIN from both sides, or RST). Packets arriving within 5 s after a close, without a SYN, are attributed to
the closed flow (`late_packets`) instead of opening a one-packet flow. `FLOW_MAX_TRACKED` (10 000) bounds
memory by evicting the least recently active flow. Packets without usable addresses or timestamps are rejected
and counted.

Packet events and flow events are separate rows. A flow's completion never re-submits its packets; packets
reference their flow through `flow_id`. Partial (still open) flows are never stored. Only completed flows are.

## 5. TLS metadata (no decryption)

`services/tls_metadata.py` reads the cleartext ClientHello and ServerHello header fields from the first bytes of a TCP
segment: offered and negotiated versions, SNI, ALPN, cipher suite and extension counts, and **JA3** (the published
algorithm, with GREASE removed). It is validated against the JA3 reference vector in `tests/test_network_metadata.py`.
It does not reassemble TCP segments. A ClientHello split across segments yields `complete: false` and no JA3,
rather than a guessed fingerprint. **JA4 is not implemented** and is reported as `unsupported`.

Optional **Zeek** enrichment (`services/zeek_tls.py`): when `ZEEK_BIN` resolves, PCAP uploads also run
`zeek -C -r` (with an argument list, not a shell). `ssl.log` fields are merged into matching flows as `tls.zeek_*`.
Without Zeek, the rest of the pipeline is unchanged and `/health.tls.zeek.available` is `false`.

TLS metadata is stored as evidence only. No current model consumes it.

## 6. Correlation (`services/correlation.py`)

Only `application_activity` and completed `network_flow` events are correlated, and only with specific evidence.
Every link stores `method`, `confidence`, `time_delta_s` and a `rationale` that the analyst can review.

**Prerequisite (all methods).** Around the activity (`CORRELATION_ADDRESS_LOOKBACK_S`), exactly **one** portal
user was seen on the client address. Otherwise the activity is marked `shared_address` and stays unlinked.
This covers NAT, shared machines and proxies.

| Method | Confidence | Evidence |
|---|---|---|
| `app_server_connection` | high | The flow is the client's own TCP connection to the portal (`APP_SERVER_PORTS`). It was open at the request time (±2 s), and carried at least the file size in the relevant direction. **Exactly one** flow may qualify; if more do, the status is `ambiguous`, and any earlier link of this kind is withdrawn when a second candidate completes later. |
| `address_time_proximity` | low | Downloads only. A flow initiated from the same client address to an external destination (outside `INTERNAL_NETWORKS`, not the portal) begins within `CORRELATION_WINDOW_S` and sends at least the file's size. At most `CORRELATION_MAX_LINKS_PER_EVENT` links per activity. |

Correlation runs when an application event is stored and again when each flow completes, because flows usually
finish after the request. The rationale always states that encrypted traffic cannot show whether a flow carried
the file. A file compressed before sending would be smaller and would not match. Network events never inherit a
`user_id`: correlated or not, they stay unattributed.

## 7. Detector boundary (teammate model integration)

`EventProcessor._pre_detection_status()` and `_detect()` are the only place inference happens.

- `DETECTOR_BACKEND=kitnet_baseline` (default) uses the existing AfterImage (100-D) → KitNET → RiskEngine → XAI
  path. The KitNET checkpoint is the **bootstrap baseline** that `app.py` trains on the bundled BoT-IoT normal
  sample when no checkpoint exists. That behaviour is unchanged. It is a prototype, so `/health.detector.final_model` is `false`.
- `DETECTOR_BACKEND=none` turns inference off: events are stored with `detection_status=unavailable`.
- The detector declares `accepted_event_types = [network_packet, network_record]` and
  `input_schema = afterimage-v1 (100 features)`. `network_flow` events are stored as `unsupported`. The flow
  schema has deliberately **not** been mapped onto the 100-D AfterImage vector.
- No model loaded gives `unavailable`, `ai_error = "Model not loaded — event was not evaluated."`, a null score and no alert.
  The frontend shows "AI unavailable", never "normal".

To integrate the final model:
1. Agree its input schema with your teammate.
2. Write an explicit mapping from the canonical event (section 1) to that schema.
3. Add it next to `_detect()`, with its own `accepted_event_types`.
4. Load the checkpoint through `services/model_adapter.py` (`verify_model`, `hot_swap_teammate_model`).
5. Set `final_model` to true only for that model.

The existing hot-swap path still assumes the 100-D AfterImage input.

## 8. Live updates

`GET /api/v1/stream/live` (SOC only) sends typed notifications, as described in `docs/API.md`. The frontend
(`frontend/src/api/live.ts`) keeps **one** ref-counted `EventSource` per tab, mounted by `SocShell`. It reconnects
with exponential backoff (1–30 s), drops duplicate or replayed message ids, and turns messages into React Query
cache invalidations, batched every 750 ms. Collector status is written directly from the stream. Views always
re-read the REST API, so an alert delivered by both SSE and polling cannot appear twice, and nothing is rendered
from data the backend did not return. While the stream is connected, polling slows (for example alerts 30 s → 120 s).
While it is reconnecting or unavailable, normal polling continues.

## 9. Database changes and migration

New: the envelope columns on `events` (with `src_ip`/`dst_ip` now nullable), `alerts.source`, the `event_correlations`
table, and the outbox columns on `file_activity`. New indexes: `ix_events_type_received`, `uq_events_dedup_key`, and
the `flow_id`, `user_id`, `source` and `detection_status` indexes.

`core/migrations.py` runs after `db.create_all()` on every start. It inspects the live schema and only adds what
is missing, so it is idempotent. SQLite cannot drop `NOT NULL` in place, so for `events` it copies the database file to
`instance/backups/` and then rebuilds the table inside one transaction, copying every row. On PostgreSQL it uses
`ALTER COLUMN … DROP NOT NULL`. Existing rows are back-filled as `event_type=network_record`, `source=legacy`, and a
`detection_status` derived from their recorded AI outcome. No rows are deleted.

## 10. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DETECTOR_BACKEND` | `kitnet_baseline` | `none` disables inference |
| `INGEST_API_KEY` | empty (open) | Require `X-Ingest-Key` on `POST /events` |
| `COLLECTOR_ALLOWED_INTERFACES` | empty (any) | Comma list of interfaces an operator may capture on |
| `COLLECTOR_PACKET_EVENTS` | `true` | Store one `network_packet` event per packet (flows are always built) |
| `COLLECTOR_QUEUE_SIZE` | 5000 | Capture → worker queue bound |
| `COLLECTOR_START_TIMEOUT_S` | 3 | Time allowed for the capture socket to open |
| `FLOW_IDLE_TIMEOUT_S` / `FLOW_ACTIVE_TIMEOUT_S` / `FLOW_MAX_TRACKED` | 30 / 300 / 10000 | Flow aggregation |
| `INTERNAL_NETWORKS` | RFC 1918, CGNAT, loopback, link-local, ULA | Organisation address space (direction, external checks) |
| `ZEEK_BIN` / `ZEEK_TIMEOUT_S` | `zeek` / 120 | Optional PCAP TLS enrichment |
| `APP_SERVER_PORTS` | `$PORT` or 5000 | Portal ports for `app_server_connection` correlation |
| `CORRELATION_WINDOW_S` | 120 | Time window for correlation |
| `CORRELATION_ADDRESS_PROXIMITY` | `true` | Enable the low-confidence rule |
| `CORRELATION_ADDRESS_LOOKBACK_S` | 3600 | Window for the one-user-per-address check |
| `CORRELATION_MAX_LINKS_PER_EVENT` | 20 | Cap on proximity links |
| `SSE_MAX_SUBSCRIBERS` / `SSE_HEARTBEAT_S` | 50 / 15 | Live stream limits |
