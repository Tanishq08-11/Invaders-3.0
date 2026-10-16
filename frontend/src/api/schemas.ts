/**
 * PROVISIONAL response contracts for the agreed /api/v1 routes.
 * Nothing here is confirmed by the backend team yet - see BACKEND_INTEGRATION.md.
 * Schemas are deliberately tolerant (optional/nullable fields) so a missing field
 * produces an "unavailable" UI state rather than an invented value.
 */
import { z } from 'zod'

const lower = (v: unknown) => (typeof v === 'string' ? v.trim().toLowerCase().replace(/[\s-]+/g, '_') : v)
const num = z.number().nullish()
const str = z.string().nullish()

export const severitySchema = z.preprocess(
  lower,
  z.enum(['critical', 'high', 'medium', 'low', 'info']),
)
// Backend lifecycle values: open | investigating | resolved | dismissed (dismissed = false positive).
const BACKEND_STATUS: Record<string, string> = { open: 'new', dismissed: 'false_positive' }
export const statusSchema = z.preprocess(
  (v) => {
    const s = lower(v)
    return typeof s === 'string' ? (BACKEND_STATUS[s] ?? s) : s
  },
  z.enum(['new', 'investigating', 'resolved', 'false_positive']),
)
export const dataSourceSchema = z.preprocess(
  lower,
  z.enum(['live', 'simulation', 'replay', 'pcap', 'unknown']).catch('unknown'),
)

const signalSchema = z
  .union([
    z.string().transform((label) => ({ code: label, label })),
    z.object({ code: str, label: z.string() }).transform((s) => ({ code: s.code ?? s.label, label: s.label })),
  ])

export const networkEventSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String).nullish(),
  timestamp: z.string(),
  device_id: str,
  src_ip: str,
  dst_ip: str,
  dst_port: num,
  protocol: str,
  bytes_out: num,
  bytes_in: num,
  packets_out: num,
  packets_in: num,
  duration_seconds: num,
  tls_sni: str,
  anomaly_score: num,
})

export const alertSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  created_at: z.string(),
  device_id: z.string(),
  destination: str,
  destination_port: num,
  risk_score: num,
  /** Optional flow metadata; shown only when the backend provides it. */
  source_ip: str,
  bytes_out: num,
  scoring_status: z.preprocess(lower, z.enum(['ok', 'failed']).catch('ok')).optional(),
  severity: severitySchema,
  status: statusSchema,
  signals: z.array(signalSchema).nullish().transform((v) => v ?? []),
  data_source: dataSourceSchema.optional(),
})

export const riskContributionSchema = z.object({
  signal: z.string(),
  label: str,
  contribution: z.number(),
  observed_value: z.union([z.string(), z.number()]).nullish(),
  baseline_value: z.union([z.string(), z.number()]).nullish(),
  explanation: str,
})

export const alertDetailSchema = alertSchema.extend({
  explanation: str,
  risk_contributions: z.array(riskContributionSchema).nullish(),
  events: z.array(networkEventSchema).nullish(),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).nullish(),
  analyst_note: str,
  model_version: str,
  updated_at: str,
})

export const alertListSchema = z.union([
  z.array(alertSchema),
  z.object({ items: z.array(alertSchema), total: z.number().nullish() }).transform((r) => r.items),
])

export const deviceTimelineSchema = z.object({
  device_id: z.string(),
  data_source: dataSourceSchema.optional(),
  events: z.array(networkEventSchema).nullish(),
  baseline: z
    .object({
      window: str,
      avg_bytes_out: num,
      avg_connections: num,
      typical_destinations: z.array(z.string()).nullish(),
    })
    .nullish(),
  unusual_destinations: z
    .array(
      z.object({
        destination: z.string(),
        first_seen: str,
        connection_count: num,
        bytes_out: num,
      }),
    )
    .nullish(),
  bursts: z
    .array(
      z.object({
        start: z.string(),
        end: str,
        connection_count: num,
        bytes_out: num,
      }),
    )
    .nullish(),
  related_alert_ids: z.array(z.union([z.string(), z.number()]).transform(String)).nullish(),
})

export const detectorSchema = z.object({
  state: z.string(),
  available: z.boolean(),
  backend: str,
  model: str,
  final_model: z.boolean().nullish(),
  description: str,
  input_schema: str,
  accepted_event_types: z.array(z.string()).nullish(),
  reason: str,
})

const distribution = z
  .union([
    z.record(z.string(), z.number()),
    z.array(z.object({ severity: z.string(), count: z.number() })).transform((rows) =>
      Object.fromEntries(rows.map((r) => [r.severity, r.count])),
    ),
  ])
  .nullish()

export const metricsSchema = z.object({
  monitored_devices: num,
  observed_events: num,
  open_incidents: num,
  high_priority_alerts: num,
  severity_distribution: distribution,
  traffic_trend: z
    .array(z.object({ timestamp: z.string(), bytes_out: num, bytes_in: num, events: num, anomalies: num }))
    .nullish(),
  data_source: dataSourceSchema.optional(),
  event_counts: z.record(z.string(), z.number()).nullish(),
  detector: detectorSchema.nullish(),
  generated_at: str,
})


const tlsCapabilitiesSchema = z
  .object({
    builtin_handshake_parser: str,
    sni: str,
    ja3: str,
    ja4: str,
    zeek: z.object({ available: z.boolean(), reason: str }).passthrough().nullish(),
  })
  .passthrough()

export const healthSchema = z.object({
  status: z.string(),
  model_loaded: z.boolean().nullish(),
  detector_state: str,
  model_version: str,
  database: str,
  ingestion: str,
  last_event_at: str,
  data_source: dataSourceSchema.optional(),
  components: z.record(z.string(), z.string()).nullish(),
  detector: detectorSchema.nullish(),
  collector: z
    .object({
      mode: z.string(),
      is_running: z.boolean().nullish(),
      is_live: z.boolean().nullish(),
      is_simulated: z.boolean().nullish(),
      live_capture_available: z.boolean().nullish(),
      live_capture_unavailable_reason: str,
      live_capture_verified: z.boolean().nullish(),
    })
    .passthrough()
    .nullish(),
  tls: tlsCapabilitiesSchema.nullish(),
  sse: z.object({ subscribers: num, max_subscribers: num }).nullish(),
  ingestion_auth: str,
  application_events_pending: num,
})

// ---- Events (GET /api/v1/events) -------------------------------------------------------

export const eventTypeSchema = z.enum(['network_packet', 'network_flow', 'network_record', 'application_activity'])
const looseRecord = z.record(z.string(), z.unknown())

export const eventSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  event_uuid: z.string(),
  event_type: z.preprocess(lower, eventTypeSchema.catch('network_record')),
  source: z.string(),
  data_source: dataSourceSchema.optional(),
  timestamp: z.string(),
  received_at: str,
  processing_status: str,
  processing_error: str,
  detection_status: z.string(),
  user_id: num,
  user: z.object({ username: str, display_name: str, department: str }).nullish(),
  action: str,
  outcome: str,
  flow_id: str,
  direction: str,
  device_id: str,
  src_ip: str,
  dst_ip: str,
  src_port: num,
  dst_port: num,
  protocol: str,
  bytes_out: num,
  bytes_in: num,
  packets_out: num,
  packets_in: num,
  duration_seconds: num,
  tls_sni: str,
  anomaly_score: num,
  ai_error: str,
  alert_id: z.union([z.string(), z.number()]).transform(String).nullish(),
})

export const correlationSchema = z.object({
  correlation_id: z.string(),
  application_event_id: str,
  network_event_id: str,
  network_flow_id: str,
  user_id: num,
  client_ip: str,
  method: z.string(),
  confidence: z.string(),
  time_delta_s: num,
  rationale: str,
  created_at: str,
  related_event: eventSchema.nullish(),
})

export const eventDetailSchema = eventSchema.extend({
  details: looseRecord.nullish(),
  correlations: z.array(correlationSchema).nullish().transform((v) => v ?? []),
  packet_event_count: num,
  flow_event_uuid: str,
  note: str,
})

export const eventListSchema = z.object({
  items: z.array(eventSchema),
  next_before_id: z.number().nullish(),
})

export const eventStatsSchema = z.object({
  by_type: z.record(z.string(), z.number()),
  by_source: z.record(z.string(), z.number()),
  by_detection_status: z.record(z.string(), z.number()),
  correlations: z.number(),
})

// ---- Collector (GET/POST /api/v1/collector/*) ---------------------------------------------

export const collectorModeSchema = z.preprocess(
  lower,
  z.enum(['stopped', 'starting', 'live', 'simulation', 'failed']),
)

export const collectorStatusSchema = z.object({
  mode: collectorModeSchema,
  is_running: z.boolean(),
  is_live: z.boolean(),
  is_simulated: z.boolean(),
  is_pcap_processing: z.boolean().nullish(),
  source: str,
  active_interface: str,
  bpf_filter: str,
  packets_captured: z.number(),
  bytes_captured: num,
  packets_dropped: num,
  events_ingested: z.number(),
  packet_events_ingested: num,
  flow_events_ingested: num,
  flows_completed: num,
  active_flows: num,
  packet_events_enabled: z.boolean().nullish(),
  corrupted_packets: num,
  collector_errors: num,
  processing_errors: z.number(),
  last_collector_error: str,
  last_processing_error: str,
  uptime_seconds: num,
  throughput_pps: num,
  live_capture_available: z.boolean(),
  live_capture_unavailable_reason: str,
  live_capture_verified: z.boolean().nullish(),
  allowed_interfaces: z.array(z.string()).nullish(),
  tls: tlsCapabilitiesSchema.nullish(),
  last_pcap: looseRecord.nullish(),
})

export const interfacesSchema = z.object({
  interfaces: z.array(
    z.object({ name: z.string(), description: str, ips: z.array(z.string()).nullish(), allowed: z.boolean() }),
  ),
  live_capture_available: z.boolean().nullish(),
  live_capture_unavailable_reason: str,
})

export const collectorActionSchema = z
  .object({
    status: z.string(),
    mode: str,
    error: str,
    warning: str,
  })
  .passthrough()

export const pcapResultSchema = z.object({
  status: z.string(),
  file: str,
  error: str,
  message: str,
  total_packets: num,
  packets_parsed: num,
  malformed_packets: num,
  events_ingested: num,
  packet_events: num,
  flow_events: num,
  flows: num,
  threats_detected: num,
  processing_errors: num,
  tls_handshakes: num,
  truncated_at_limit: z.boolean().nullish(),
  stopped_by_user: z.boolean().nullish(),
  zeek: z.object({ available: z.boolean(), tls_records: num, error: str }).nullish(),
})

export const alertUpdateSchema = z.object({
  status: statusSchema.optional(),
  note: z.string().max(2000).optional(),
})
