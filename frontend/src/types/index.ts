import type { z } from 'zod'
import type {
  alertDetailSchema,
  alertSchema,
  alertUpdateSchema,
  dataSourceSchema,
  deviceTimelineSchema,
  healthSchema,
  metricsSchema,
  networkEventSchema,
  riskContributionSchema,
  severitySchema,
  statusSchema,
} from '@/api/schemas'

export type Severity = z.infer<typeof severitySchema>
export type AlertStatus = z.infer<typeof statusSchema>
export type DataSource = z.infer<typeof dataSourceSchema>
export type NetworkEvent = z.infer<typeof networkEventSchema>
export type Alert = z.infer<typeof alertSchema>
export type AlertDetail = z.infer<typeof alertDetailSchema>
export type RiskContribution = z.infer<typeof riskContributionSchema>
export type DeviceTimeline = z.infer<typeof deviceTimelineSchema>
export type Metrics = z.infer<typeof metricsSchema>
export type Health = z.infer<typeof healthSchema>
export type AlertUpdate = z.infer<typeof alertUpdateSchema>

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive']
