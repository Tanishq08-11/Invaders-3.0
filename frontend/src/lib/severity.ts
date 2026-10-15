import type { AlertStatus, Severity } from '@/types'

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#F59E0B',
  low: '#0284C7',
  info: '#64748B',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export const STATUS_COLOR: Record<AlertStatus, string> = {
  new: '#0078D4',
  investigating: '#3B82F6',
  resolved: '#34D399',
  false_positive: '#64748B',
}

export const isOpen = (s: AlertStatus) => s === 'new' || s === 'investigating'
