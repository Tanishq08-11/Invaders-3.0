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
  z.enum(['live', 'replay', 'unknown']).catch('unknown'),
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
  generated_at: str,
})

export const healthSchema = z.object({
  status: z.string(),
  model_loaded: z.boolean().nullish(),
  model_version: str,
  database: str,
  ingestion: str,
  last_event_at: str,
  data_source: dataSourceSchema.optional(),
})

export const alertUpdateSchema = z.object({
  status: statusSchema.optional(),
  note: z.string().max(2000).optional(),
})
