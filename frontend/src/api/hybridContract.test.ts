/**
 * Parses the real backend responses written by tests/test_hybrid_pipeline.py
 * (packets → flow → TrustLab KitNET → D1–D28 → hybrid alert → Flask API).
 */
import { describe, expect, it } from 'vitest'
import fixture from '../test/fixtures/hybrid_pipeline.json'
import { alertDetailSchema, alertListSchema, eventDetailSchema } from './schemas'

describe('hybrid pipeline contract', () => {
  it('alert detail keeps AI + rule fields', () => {
    const a = alertDetailSchema.parse(fixture.alert_detail)
    expect(['ai', 'rules', 'hybrid']).toContain(a.detection_source)
    expect(a.anomaly_threshold).toBe(0.07018400015809657)
    expect(a.model_status).toBe('scored')
    expect(a.signals.some((s) => s.code === 'D20')).toBe(true)
    expect(a.hybrid_risk?.final_risk_score).toBe(a.risk_score)
  })
  it('alert list and event detail parse', () => {
    expect(alertListSchema.parse(fixture.alert_list)[0].detection_source).toBe(fixture.alert_detail.detection_source)
    const e = eventDetailSchema.parse(fixture.event_detail)
    expect((e.detection_summary?.triggered as string[]).includes('D20')).toBe(true)
    expect(e.hybrid_risk?.model_status).toBe('scored')
  })
})
