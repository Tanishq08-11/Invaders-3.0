import type { z } from 'zod'
import type {
  alertDetailSchema,
  alertSchema,
  alertUpdateSchema,
  collectorActionSchema,
  collectorModeSchema,
  collectorStatusSchema,
  correlationSchema,
  dataSourceSchema,
  detectorSchema,
  deviceTimelineSchema,
  eventDetailSchema,
  eventListSchema,
  eventSchema,
  eventStatsSchema,
  eventTypeSchema,
  healthSchema,
  interfacesSchema,
  metricsSchema,
  networkEventSchema,
  pcapResultSchema,
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
export type Detector = z.infer<typeof detectorSchema>
export type EventType = z.infer<typeof eventTypeSchema>
export type PipelineEvent = z.infer<typeof eventSchema>
export type PipelineEventDetail = z.infer<typeof eventDetailSchema>
export type EventList = z.infer<typeof eventListSchema>
export type EventStats = z.infer<typeof eventStatsSchema>
export type Correlation = z.infer<typeof correlationSchema>
export type CollectorMode = z.infer<typeof collectorModeSchema>
export type CollectorStatus = z.infer<typeof collectorStatusSchema>
export type CaptureInterfaces = z.infer<typeof interfacesSchema>
export type CollectorAction = z.infer<typeof collectorActionSchema>
export type PcapResult = z.infer<typeof pcapResultSchema>

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive']
