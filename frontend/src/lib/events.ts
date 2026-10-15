import type { EventType, PipelineEvent } from '@/types'

export const EVENT_TYPE_LABEL: Record<EventType, string> = {
  application_activity: 'Application',
  network_flow: 'Network flow',
  network_packet: 'Packet',
  network_record: 'Network record',
}

/** One-line description of an event for tables and correlation lists. */
export function eventSummary(e: PipelineEvent): string {
  if (e.event_type === 'application_activity') {
    const who = e.user?.username ?? (e.user_id != null ? `user #${e.user_id}` : 'unknown user')
    return `${who} · ${e.action ?? 'action'} ${e.outcome ?? ''}`.trim()
  }
  const dst = `${e.dst_ip ?? '—'}${e.dst_port != null ? `:${e.dst_port}` : ''}`
  return `${e.src_ip ?? '—'}${e.src_port != null ? `:${e.src_port}` : ''} → ${dst} ${e.protocol ?? ''}`.trim()
}
