"""
Detector contract
==================
Every detector:
  • declares `event_types` it evaluates and the data it `requires`;
  • `evaluate(ctx)` → DetectorResult, read-only (no state changes);
  • `commit(ctx, result, flagged)` → updates its baselines/state afterwards. `flagged`
    is True when the event raised a HIGH/CRITICAL signal or an alert; detectors must not
    learn "normal" from flagged data (baseline-poisoning guard).

Statuses
  triggered       evidence met the detector's documented threshold
  clear           evaluated with the required data; threshold not met
  not_evaluated   required data / history / enrichment unavailable — NEVER a clear
  error           the detector raised; recorded, other detectors unaffected

Scores are rule weights on a 0–100 scale for the documented combination policy. They
are not probabilities and never stand in for an AI anomaly score.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

TRIGGERED, CLEAR, NOT_EVALUATED, ERROR = "triggered", "clear", "not_evaluated", "error"
SEVERITY_SCORE = {"LOW": 20.0, "MEDIUM": 45.0, "HIGH": 70.0, "CRITICAL": 90.0}
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Risk-combination groups (see RiskEngine.combine_rule_signals)
G_EXFIL, G_DESTINATION, G_BEHAVIOUR, G_PROTOCOL, G_IDENTITY, G_CHAIN, G_HEALTH = (
    "exfiltration_volume", "destination", "behaviour", "protocol", "identity", "multi_stage", "telemetry_health",
)


@dataclass
class DetectorResult:
    detector_id: str
    status: str
    severity: Optional[str] = None
    score: Optional[float] = None
    observed: Dict[str, Any] = field(default_factory=dict)
    baseline: Optional[Dict[str, Any]] = None
    threshold: Optional[Dict[str, Any]] = None
    evidence: List[str] = field(default_factory=list)
    availability: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    evidence_only: bool = False      # contextual evidence: capped weight in risk combination
    dedup_scope: Optional[str] = None  # overrides the per-event dedup key (window/episode signals)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def summary(self) -> Dict[str, Any]:
        out = {"status": self.status}
        if self.status == TRIGGERED:
            out.update(severity=self.severity, score=self.score, reason=self.reason, evidence=list(self.evidence))
        if self.status in (NOT_EVALUATED, ERROR):
            out["reason"] = self.reason
        return out


class Detector:
    id = "D0"
    name = "detector"
    version = "1.0"
    group = G_BEHAVIOUR
    category = "security"          # "telemetry_health" signals never create security alerts
    event_types: tuple = ()
    requires: tuple = ()           # human-readable list of required data

    def evaluate(self, ctx) -> DetectorResult:  # pragma: no cover - interface
        raise NotImplementedError

    def commit(self, ctx, result: DetectorResult, flagged: bool) -> None:
        """Update baselines/state after the event's results are combined."""

    # ---- helpers -------------------------------------------------------------------
    def result(self, status, **kw) -> DetectorResult:
        return DetectorResult(detector_id=self.id, status=status, **kw)

    def not_evaluated(self, reason: str, missing: Optional[List[str]] = None, **kw) -> DetectorResult:
        availability = kw.pop("availability", {})
        if missing:
            availability = {**availability, "missing": missing}
        return self.result(NOT_EVALUATED, reason=reason, availability=availability, **kw)

    def clear(self, reason: str = "", **kw) -> DetectorResult:
        return self.result(CLEAR, reason=reason, **kw)

    def triggered(self, severity: str, reason: str, score: Optional[float] = None, **kw) -> DetectorResult:
        return self.result(TRIGGERED, severity=severity, score=SEVERITY_SCORE[severity] if score is None else score,
                           reason=reason, **kw)

    def describe(self, ctx=None) -> Dict[str, Any]:
        return {
            "detector_id": self.id, "name": self.name, "version": self.version, "group": self.group,
            "category": self.category, "event_types": list(self.event_types), "requires": list(self.requires),
        }
