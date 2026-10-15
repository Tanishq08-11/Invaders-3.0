"""
Rule-based detection engine
============================
Runs the registered detectors (services/detection/detectors/) on a stored event,
independently of AI inference:

  1. Skip if the event already has a detection summary (idempotent re-processing).
  2. Resolve the entity (registered device / internal address / session user).
  3. evaluate() every applicable detector — each in its own try/except, so one failure
     is recorded as status "error" and never suppresses the others. D24 (multi-stage)
     runs last because it reads the other results.
  4. Combine triggered security signals (RiskEngine.combine_rule_signals).
  5. commit() each detector's state with `flagged` = event raised HIGH/CRITICAL, reached
     the alert threshold, or already has an AI alert → flagged data never trains baselines.
  6. Persist triggered/error results as DetectionSignal rows (dedup keys make this
     idempotent); store clear/not_evaluated outcomes only in the event's compact summary.
  7. Alert: when the combined rule score ≥ RULE_ALERT_MIN_SCORE or any signal is HIGH+.
     If the event (or another event of the same flow) already has an open alert, the
     signals are merged into it (detection_source "hybrid" when the model raised it);
     otherwise a "rules" alert is created with NULL model scores.

Packet events are not evaluated here: each packet is inside a completed flow, and
evaluating both would double-count one connection.
"""
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import current_app

from config import Config
from core.database import db
from core.models import (
    EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_PACKET, EVENT_NETWORK_RECORD,
    SIGNAL_ERROR, SIGNAL_TRIGGERED, Alert, DetectionSignal, Event,
)
from ml.risk_engine import combine_rule_signals
from services.detection import identity
from services.detection.base import CLEAR, ERROR, NOT_EVALUATED, SEVERITY_ORDER, TRIGGERED, DetectorResult
from services.detection.baselines import Baselines
from services.detection.features import EventFeatures

log = logging.getLogger(__name__)
ENGINE_VERSION = "1.0"


def cfg(name, default=None):
    try:
        return current_app.config.get(name, getattr(Config, name, default))
    except RuntimeError:
        return getattr(Config, name, default)


class DetectionContext:
    def __init__(self, event: Optional[Event], features: Optional[EventFeatures], now: float):
        self.event = event
        self.f = features
        self.now = now
        self.cfg = cfg
        self.baselines = Baselines(cfg)
        self.results: Dict[str, DetectorResult] = {}
        self.cache: Dict[str, Any] = {}
        self.after_commit: List = []       # callbacks(flagged) run once after all commits
        self.resolution = None

    @property
    def entity(self) -> Optional[str]:
        return self.f.entity_key if self.f else None

    @property
    def ts(self) -> float:
        return (self.f.ts if self.f and self.f.ts else None) or self.now

    @property
    def sample_key(self) -> str:
        return self.event.event_uuid if self.event is not None else f"sweep:{int(self.now)}"


class DetectionEngine:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        from services.detection.detectors import all_detectors
        self.detectors = all_detectors()
        self._run_lock = threading.RLock()   # stateful detectors: one evaluation at a time
        self.counters = {"events_evaluated": 0, "signals_triggered": 0, "detector_errors": 0,
                         "rule_alerts_created": 0, "alerts_merged": 0}

    @classmethod
    def get_instance(cls) -> "DetectionEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # ------------------------------------------------------------------ registry
    def enabled_ids(self) -> set:
        disabled = set(cfg("DETECTORS_DISABLED") or [])
        return {d.id for d in self.detectors if d.id not in disabled}

    def describe(self) -> List[Dict[str, Any]]:
        enabled = self.enabled_ids()
        out = []
        for d in self.detectors:
            info = d.describe()
            info["enabled"] = bool(cfg("DETECTION_ENABLED")) and d.id in enabled
            dep = getattr(d, "dependencies", None)
            if dep:
                info["dependencies"] = dep()
            out.append(info)
        return out

    def _applicable(self, event_type: str):
        enabled = self.enabled_ids()
        dets = [d for d in self.detectors if event_type in d.event_types and d.id in enabled]
        return sorted(dets, key=lambda d: d.id == "D24")   # multi-stage last

    # ------------------------------------------------------------------ entity
    def _resolve_entity(self, ev: Event, f: EventFeatures, ctx: DetectionContext):
        if ev.event_type == EVENT_APPLICATION:
            if ev.user_id:
                f.entity_key, f.entity_kind = f"user:{ev.user_id}", "user"
            return
        key, kind, res = identity.entity_for_network(f.internal_ip, f.ts, f.init_mac if f.initiator_internal else None)
        f.entity_key, f.entity_kind = key, kind
        ctx.resolution = res
        if kind == "device":
            f.device_key = res["device_key"]
            ev.device_id = res["device_key"]
            identity.mark_seen(res["device"], f.end_ts or f.ts)

    # ------------------------------------------------------------------ run
    def run(self, ev: Event, on_alert=None) -> Optional[Dict[str, Any]]:
        if not cfg("DETECTION_ENABLED"):
            return None
        if ev.event_type == EVENT_NETWORK_PACKET:
            return None
        if ev.detection_summary_json:
            return {"skipped": "already evaluated"}
        with self._run_lock:
            return self._run(ev, on_alert)

    def _run(self, ev: Event, on_alert) -> Dict[str, Any]:
        f = EventFeatures.from_event(ev)
        ctx = DetectionContext(ev, f, now=time.time())
        self._resolve_entity(ev, f, ctx)
        ev.entity_key = f.entity_key

        for det in self._applicable(ev.event_type):
            try:
                r = det.evaluate(ctx)
            except Exception as exc:
                log.exception("[detection] %s failed on %s", det.id, ev.event_uuid)
                r = det.result(ERROR, reason=f"Detector error: {type(exc).__name__}")
                self.counters["detector_errors"] += 1
            ctx.results[det.id] = r

        security = [(d, ctx.results[d.id]) for d in self._applicable(ev.event_type)
                    if ctx.results[d.id].status == TRIGGERED and d.category == "security"]
        combined = combine_rule_signals([
            {"score": r.score, "group": d.group, "evidence_only": r.evidence_only} for d, r in security
        ]) if security else None
        high = any(SEVERITY_ORDER.get(r.severity, 0) >= 3 for _, r in security)
        alert_due = bool(security) and (high or combined["rule_score"] >= float(cfg("RULE_ALERT_MIN_SCORE")))
        flagged = alert_due or ev.alert_id is not None

        for det in self._applicable(ev.event_type):
            r = ctx.results[det.id]
            if r.status == ERROR:
                continue
            try:
                det.commit(ctx, r, flagged)
            except Exception as exc:
                log.exception("[detection] %s commit failed on %s", det.id, ev.event_uuid)
                ctx.results[det.id] = det.result(ERROR, reason=f"Detector state update failed: {type(exc).__name__}")
        for cb in ctx.after_commit:
            try:
                cb(flagged)
            except Exception:
                log.exception("[detection] post-commit hook failed on %s", ev.event_uuid)

        signals = self._persist(ctx, ev)
        alert_dict = None
        if alert_due:
            alert_dict = self._alert(ev, f, ctx, security, combined, signals, on_alert)

        ev.detection_summary_json = json.dumps({
            "engine_version": ENGINE_VERSION,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "entity_key": f.entity_key,
            "entity_kind": f.entity_kind,
            "results": {k: r.summary() for k, r in sorted(ctx.results.items())},
            "triggered": sorted(k for k, r in ctx.results.items() if r.status == TRIGGERED),
            "not_evaluated": sorted(k for k, r in ctx.results.items() if r.status == NOT_EVALUATED),
            "errors": sorted(k for k, r in ctx.results.items() if r.status == ERROR),
            "rule_score": combined["rule_score"] if combined else None,
            "rule_severity": combined["severity"] if combined else None,
            "alert_created": bool(alert_dict),
            "flagged": flagged,
        })
        self.counters["events_evaluated"] += 1
        return {"signals": [s.to_dict() for s in signals], "combined": combined, "alert": alert_dict,
                "summary": json.loads(ev.detection_summary_json)}

    # ------------------------------------------------------------------ persistence
    def _persist(self, ctx: DetectionContext, ev: Optional[Event]) -> List[DetectionSignal]:
        rows = []
        by_id = {d.id: d for d in self.detectors}
        for det_id, r in ctx.results.items():
            if r.status not in (TRIGGERED, ERROR):
                continue
            det = by_id[det_id]
            dedup = r.dedup_scope or f"{det_id}:{ev.event_uuid if ev is not None else ctx.sample_key}"
            if r.status == ERROR:
                dedup = f"{dedup}:error"
            if DetectionSignal.query.filter_by(dedup_key=dedup[:200]).first() is not None:
                continue   # same window/episode already signalled
            entity = ctx.entity or r.observed.get("entity_key")
            row = DetectionSignal(
                signal_uuid=f"SIG-{uuid.uuid4().hex[:12].upper()}",
                dedup_key=dedup[:200],
                event_id=ev.id if ev is not None else None,
                entity_key=entity[:96] if entity else None,
                detector_id=det_id, detector_name=det.name, detector_version=det.version,
                category=det.category,
                status=SIGNAL_TRIGGERED if r.status == TRIGGERED else SIGNAL_ERROR,
                severity=r.severity, score=r.score,
                observed_json=json.dumps(r.observed, default=str),
                baseline_json=json.dumps(r.baseline, default=str) if r.baseline is not None else None,
                threshold_json=json.dumps(r.threshold, default=str) if r.threshold is not None else None,
                evidence_json=json.dumps(r.evidence, default=str),
                availability_json=json.dumps(r.availability, default=str) if r.availability else None,
                config_json=json.dumps({"engine": ENGINE_VERSION, "group": det.group, "evidence_only": r.evidence_only}),
                reason=r.reason,
            )
            db.session.add(row)
            rows.append(row)
            if r.status == TRIGGERED:
                self.counters["signals_triggered"] += 1
        db.session.flush()
        return rows

    # ------------------------------------------------------------------ alerts
    def _alert(self, ev, f, ctx, security, combined, signals, on_alert) -> Optional[Dict[str, Any]]:
        sig_rows = {s.detector_id: s for s in signals if s.status == SIGNAL_TRIGGERED}
        entries = [{"detector_id": d.id, "name": d.name, "severity": r.severity, "score": r.score,
                    "reason": r.reason, "signal_id": sig_rows[d.id].signal_uuid if d.id in sig_rows else None}
                   for d, r in security]
        explanation = "Rule-based detection — " + " ".join(f"[{e['detector_id']} {e['name']}] {e['reason']}" for e in entries)

        alert = db.session.get(Alert, ev.alert_id) if ev.alert_id else None
        if alert is None and ev.flow_id:
            # A packet of the same connection may already have raised a (model) alert.
            alert = (Alert.query.join(Event, Event.alert_id == Alert.id)
                     .filter(Event.flow_id == ev.flow_id, Alert.status.in_(("open", "investigating"))).first())
        if alert is not None:
            existing = {e.get("detector_id") for e in alert.rule_signals if isinstance(e, dict)}
            merged = alert.rule_signals + [e for e in entries if e["detector_id"] not in existing]
            alert.rule_signals_json = json.dumps(merged, default=str)
            alert.signal_count = len(merged)
            alert.rule_score = max(alert.rule_score or 0.0, combined["rule_score"])
            if alert.detection_source == "ai":
                alert.detection_source = "hybrid"
            alert.risk_score = max(alert.risk_score or 0.0, combined["rule_score"])
            if SEVERITY_ORDER.get(combined["severity"], 0) > SEVERITY_ORDER.get(alert.severity, 0):
                alert.severity = combined["severity"]
            alert.explanation = (alert.explanation + " | " if alert.explanation else "") + explanation
            alert.updated_at = datetime.now(timezone.utc)
            ev.alert_id = alert.id
            self.counters["alerts_merged"] += 1
        else:
            alert = Alert(
                alert_uuid=f"ALT-{uuid.uuid4().hex[:10].upper()}",
                severity=combined["severity"], risk_score=combined["rule_score"], rule_score=combined["rule_score"],
                anomaly_score=None, z_score=None, confidence=None,      # no model output exists
                detection_source="rules", rule_signals_json=json.dumps(entries, default=str),
                signal_count=len(entries), event_type=ev.event_type, entity_key=f.entity_key,
                user_id=ev.user_id if ev.event_type == EVENT_APPLICATION else None,
                src_ip=ev.src_ip, dst_ip=ev.dst_ip, src_port=ev.src_port, dst_port=ev.dst_port,
                protocol=ev.protocol, bytes_transferred=int(f.outbound_bytes or ev.bytes_transferred or 0),
                source=ev.source, off_hours=ctx.results.get("D4") is not None and ctx.results["D4"].status == TRIGGERED,
                is_external_dst=bool(f.external_ip), evidence_json=json.dumps([]), risk_factors_json=json.dumps([]),
                explanation=explanation, mitigation_json=json.dumps(_mitigation(entries)), status="open",
            )
            db.session.add(alert)
            db.session.flush()
            ev.alert_id = alert.id
            self.counters["rule_alerts_created"] += 1
        for s in signals:
            if s.status == SIGNAL_TRIGGERED:
                s.alert_id = alert.id
        if on_alert:
            on_alert(ev, alert)
        return alert.to_dict()

    # ------------------------------------------------------------------ periodic sweep
    def sweep(self) -> Dict[str, Any]:
        """Telemetry detectors (D11 device silence, D25 telemetry health) — not tied to an event."""
        results = {}
        signals = []
        with self._run_lock:
            enabled = self.enabled_ids()
            for det in self.detectors:
                if "sweep" not in det.event_types or det.id not in enabled:
                    continue
                ctx = DetectionContext(None, None, now=time.time())
                try:
                    outs = det.sweep(ctx)
                except Exception as exc:
                    log.exception("[detection] sweep %s failed", det.id)
                    outs = [det.result(ERROR, reason=f"Detector error: {type(exc).__name__}")]
                results[det.id] = [o.summary() | {"entity": o.observed.get("entity_key"), "reason": o.reason} for o in outs]
                for o in outs:
                    if o.status in (TRIGGERED, ERROR):
                        ctx.results = {det.id: o}
                        signals += self._persist(ctx, None)
        return {"results": results, "signals": [s.to_dict() for s in signals]}


def _mitigation(entries) -> List[str]:
    steps = ["Review the listed signals and their observed values against the stated baselines."]
    ids = {e["detector_id"] for e in entries}
    if ids & {"D1", "D5", "D6", "D7", "D9", "D18"}:
        steps.append("Confirm with the device owner or data owner whether the outbound transfer was authorised.")
    if ids & {"D16"}:
        steps.append("Review which portal files were downloaded; application downloads do not prove external transfer.")
    if ids & {"D12", "D17", "D21", "D20", "D23"}:
        steps.append("Check the destination/protocol against the egress policy and block if unapproved.")
    if ids & {"D13", "D14", "D15", "D27"}:
        steps.append("Verify the sessions with the user; reset credentials if the activity is not recognised.")
    if ids & {"D28", "D22"}:
        steps.append("Inspect the internal host for unexpected administrative connections or scanning.")
    steps.append("Resolve the alert as benign / false positive to let these observations re-enter the baseline.")
    return steps
