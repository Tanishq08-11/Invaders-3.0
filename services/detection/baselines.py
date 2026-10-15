"""
Behavioural baselines (independent of the AI model)
=====================================================
• Samples: one row per (entity, metric, sample_key) — idempotent; queries are bounded by
  BASELINE_WINDOW_DAYS and BASELINE_MAX_SAMPLES; only `trusted` samples form baselines.
• Robust statistics: median and MAD (scaled by 1.4826). A personalised baseline needs at
  least BASELINE_MIN_SAMPLES samples; with fewer, `stats()` returns None and detectors
  report not_evaluated. MAD = 0 (e.g. identical backups) is reported explicitly and a
  documented floor scale is used instead of dividing by zero.
• Poisoning guard: samples from flagged events are stored with trusted=False. An analyst
  disposition of benign / false_positive on the alert re-trusts them (trust_event_samples).
• State: small JSON documents per (entity, key) for stateful detectors (EWMA/CUSUM, hour
  histograms, rolling windows, fingerprint history), bounded by each detector.
"""
import json
import math
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError

from core.database import db
from core.models import ORG_ENTITY, BaselineSample, BehaviorState, DestinationHistory
from core.timeutil import naive_utc

MAD_SCALE = 1.4826


@dataclass
class RobustStats:
    n: int
    median: float
    mad: float
    p90: float
    minimum: float
    maximum: float
    mad_zero: bool

    def scale(self, floor: float) -> float:
        if self.mad > 0:
            return MAD_SCALE * self.mad
        # MAD = 0: all (or most) samples identical. Use 5% of the median or the floor.
        return max(abs(self.median) * 0.05, floor)

    def robust_z(self, x: float, floor: float) -> float:
        return (x - self.median) / self.scale(floor)

    def as_dict(self) -> Dict[str, Any]:
        return {"samples": self.n, "median": round(self.median, 4), "mad": round(self.mad, 4),
                "p90": round(self.p90, 4), "min": round(self.minimum, 4), "max": round(self.maximum, 4),
                "mad_zero": self.mad_zero}


def robust_stats(values: List[float]) -> Optional[RobustStats]:
    vals = sorted(v for v in values if v is not None and not math.isnan(v))
    if not vals:
        return None
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    p90 = vals[min(len(vals) - 1, int(round(0.9 * (len(vals) - 1))))]
    return RobustStats(len(vals), med, mad, p90, vals[0], vals[-1], mad == 0)


class Baselines:
    def __init__(self, cfg):
        self.cfg = cfg

    # ---- samples -------------------------------------------------------------------
    def values(self, entity: str, metric: str, now_ts: float, window_days: Optional[float] = None) -> List[float]:
        days = window_days or float(self.cfg("BASELINE_WINDOW_DAYS"))
        rows = (
            db.session.query(BaselineSample.value)
            .filter(BaselineSample.entity_key == entity, BaselineSample.metric == metric,
                    BaselineSample.trusted.is_(True),
                    BaselineSample.observed_at >= naive_utc(now_ts - days * 86400),
                    BaselineSample.observed_at <= naive_utc(now_ts))
            .order_by(BaselineSample.observed_at.desc())
            .limit(int(self.cfg("BASELINE_MAX_SAMPLES")))
            .all()
        )
        return [r[0] for r in rows]

    def stats(self, entity: str, metric: str, now_ts: float, min_samples: Optional[int] = None,
              window_days: Optional[float] = None) -> Optional[RobustStats]:
        vals = self.values(entity, metric, now_ts, window_days)
        if len(vals) < int(min_samples or self.cfg("BASELINE_MIN_SAMPLES")):
            return None
        return robust_stats(vals)

    def sample_count(self, entity: str, metric: str, now_ts: float) -> int:
        return len(self.values(entity, metric, now_ts))

    def add_sample(self, entity: str, metric: str, value: float, ts: float, sample_key: str,
                   event_id: Optional[int], trusted: bool) -> None:
        if entity is None or value is None or ts is None or math.isnan(value):
            return
        exists = BaselineSample.query.filter_by(entity_key=entity, metric=metric, sample_key=sample_key).first()
        if exists:
            return  # repeated processing of the same observation
        db.session.add(BaselineSample(entity_key=entity, metric=metric, value=float(value),
                                      observed_at=naive_utc(ts), sample_key=sample_key[:96],
                                      event_id=event_id, trusted=bool(trusted)))

    # ---- state ---------------------------------------------------------------------
    def get_state(self, entity: str, key: str) -> Dict[str, Any]:
        row = BehaviorState.query.filter_by(entity_key=entity, state_key=key).first()
        if row is None:
            return {}
        try:
            return json.loads(row.state_json or "{}")
        except ValueError:
            return {}

    def set_state(self, entity: str, key: str, state: Dict[str, Any]) -> None:
        row = BehaviorState.query.filter_by(entity_key=entity, state_key=key).first()
        payload = json.dumps(state, default=str)
        if row is None:
            db.session.add(BehaviorState(entity_key=entity, state_key=key, state_json=payload))
        else:
            row.state_json = payload
            row.updated_at = datetime.now(timezone.utc)

    # ---- destination history ---------------------------------------------------------
    def destination(self, entity: str, destination: str) -> Optional[DestinationHistory]:
        return DestinationHistory.query.filter_by(entity_key=entity, destination=destination).first()

    def destination_popularity(self, destination: str) -> int:
        """Number of distinct (non-org) entities that used this destination."""
        return DestinationHistory.query.filter(
            DestinationHistory.destination == destination, DestinationHistory.entity_key != ORG_ENTITY
        ).count()

    def org_flow_total(self) -> int:
        total = db.session.query(db.func.coalesce(db.func.sum(DestinationHistory.flow_count), 0)).filter(
            DestinationHistory.entity_key == ORG_ENTITY).scalar()
        return int(total or 0)

    def touch_destination(self, entity: Optional[str], destination: str, kind: str, ts: float, outbound: float) -> None:
        when = naive_utc(ts)
        for ent in filter(None, (entity, ORG_ENTITY)):
            row = self.destination(ent, destination)
            if row is None:
                db.session.add(DestinationHistory(entity_key=ent, destination=destination[:255], dest_kind=kind,
                                                  first_seen=when, last_seen=when, flow_count=1,
                                                  outbound_bytes=int(outbound or 0)))
                db.session.flush()
            else:
                row.flow_count += 1
                row.outbound_bytes = (row.outbound_bytes or 0) + int(outbound or 0)
                row.last_seen = max(row.last_seen, when)
                row.first_seen = min(row.first_seen, when)


def trust_event_samples(event_ids: List[int]) -> int:
    """Explicit trusted-baseline policy: called when an analyst marks an alert benign/false positive."""
    if not event_ids:
        return 0
    n = BaselineSample.query.filter(BaselineSample.event_id.in_(event_ids), BaselineSample.trusted.is_(False)) \
        .update({BaselineSample.trusted: True}, synchronize_session=False)
    return int(n or 0)


def prune(retention_days: float) -> int:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)
    n = BaselineSample.query.filter(BaselineSample.observed_at < cutoff).delete(synchronize_session=False)
    return int(n or 0)


__all__ = ["Baselines", "RobustStats", "robust_stats", "trust_event_samples", "prune", "IntegrityError"]
