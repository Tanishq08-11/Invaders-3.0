"""
Event Processor — the single event-processing boundary.
=========================================================
Every event, whatever its origin, goes through `EventProcessor.submit()`:

    network_packet        live capture / PCAP / simulation   (services/live_collector.py)
    network_flow          flow aggregator                    (services/flow_aggregator.py)
    network_record        POST /api/v1/events, dataset replay
    application_activity  portal file operations             (api/routes_files.py)

Stages, each recorded on the event row so a later failure never loses an earlier one:

  1. validate + normalise            → reject (nothing stored) on invalid input
  2. persist (COMMIT)                → processing_status=stored
  3. AI detection — the authoritative TrustLab KitNET bundle (ml/kitnet_trustlab_bundle.pkl)
     on the canonical 78-feature vector (ml/trustlab_features.py), for completed flows and
     flow records only     → detection_status = scored | unavailable | unsupported | failed | not_applicable
  4. rule detection — DetectionEngine.run() (D1–D28) on flows, records and application
     events; result in detection_summary_json (triggered / clear / not_evaluated / error)
  5. hybrid correlation (ml/risk_engine.hybrid_risk): KitNET result + rule results → one
     final risk and at most ONE alert per event (detection_source ai | rules | hybrid)
  6. device profile update
  7. application ↔ network correlation (application events and completed flows)
                                     → processing_status = complete | downstream_error
  8. broadcast a typed message to SSE subscribers

No stage ever substitutes a score: when inference does not run the score stays NULL,
detection_status explains why, and the model contributes nothing to the hybrid decision.
Rule-detector outputs are never model inputs.
"""
from typing import Dict, Any, Optional
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
import queue
import threading
import os

from config import Config
from core.database import db
from core.models import (
    Event, Alert, Device,
    EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_PACKET, EVENT_NETWORK_RECORD,
    EVENT_TYPES, NETWORK_EVENT_TYPES, TRAFFIC_EVENT_TYPES,
    SOURCE_API, SOURCE_APPLICATION,
    DETECTION_FAILED, DETECTION_NOT_APPLICABLE, DETECTION_PENDING, DETECTION_SCORED,
    DETECTION_UNAVAILABLE, DETECTION_UNSUPPORTED,
    PROCESSING_COMPLETE, PROCESSING_DOWNSTREAM_ERROR,
)
from ml.risk_engine import RiskEngine, hybrid_risk
from ml.trustlab_adapter import TrustLabKitNET
from ml.trustlab_features import IMPUTED, OBSERVED, ZERO, build_feature_vector

log = logging.getLogger(__name__)

MODEL_NOT_LOADED = "Model not loaded — event was not evaluated."
MODEL_NAME = "kitnet_trustlab_bundle"
DETECTOR_INPUT_SCHEMA = "trustlab-78 (74 CICFlowMeter flow features + HourSin/HourCos/DaySin/DayCos)"
# Packets are not scored: every packet is inside a completed flow, which is.
DETECTOR_ACCEPTED_TYPES = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
RULE_EVENT_TYPES = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, EVENT_APPLICATION)
# Features that describe the connection rather than measure it (not counted towards coverage).
_NON_MEASUREMENT = {"Src Port", "Dst Port", "Protocol", "HourSin", "HourCos", "DaySin", "DayCos"}


class EventValidationError(ValueError):
    """Input that cannot form a valid event; nothing is stored."""


class EventProcessor:
    """Singleton that owns the detector pipeline and processes every event."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self, bundle_path: Optional[str] = None):
        self.bundle_path = bundle_path or Config.TRUSTLAB_BUNDLE_PATH
        # The authoritative model: loaded read-only from the bundle, never trained or modified here.
        self.kitnet = TrustLabKitNET()
        self.feature_names: list = []
        self.medians: Dict[str, float] = {}
        self.threshold: Optional[float] = None
        self.bundle_sha256: Optional[str] = None
        # Kept only for the legacy /model/thresholds route; it takes no part in the hybrid decision.
        self.risk_engine = RiskEngine(
            z_low=Config.Z_THRESHOLD_LOW,
            z_med=Config.Z_THRESHOLD_MEDIUM,
            z_high=Config.Z_THRESHOLD_HIGH,
            z_crit=Config.Z_THRESHOLD_CRITICAL,
        )

        self.detector_backend = Config.DETECTOR_BACKEND
        self.model_loaded = False
        self.model_load_error: Optional[str] = None
        self._active_model_version_id: Optional[int] = None
        self._detect_lock = threading.Lock()

        # SSE subscriber queues
        self._subscribers: list[queue.Queue] = []
        self._sub_lock = threading.Lock()
        self._seq = 0

        # Counters for /metrics and /health — they count outcomes, not attempts.
        self._counter_lock = threading.Lock()
        self.events_received = 0          # submissions that passed validation
        self.events_rejected = 0          # invalid input, nothing stored
        self.events_ingested = 0          # rows committed
        self.events_duplicate = 0         # idempotent re-submissions (not stored twice)
        self.persist_failures = 0         # database refused the row
        self.events_evaluated = 0         # detector produced a score
        self.detection_unavailable = 0
        self.detection_unsupported = 0
        self.detection_failures = 0
        self.rule_evaluations = 0         # DetectionEngine.run() completed on an event
        self.rule_failures = 0            # DetectionEngine.run() raised (recorded on the event)
        self.downstream_failures = 0      # alert/device/correlation stage failed after the row was stored
        self.alerts_created = 0
        self.true_positives = 0
        self.false_positives = 0

        self.reload_model()

    # ------------------------------------------------------------------
    # Singleton accessor
    # ------------------------------------------------------------------
    @classmethod
    def get_instance(cls) -> "EventProcessor":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @property
    def events_failed(self) -> int:
        """Back-compat aggregate: storage failures + detector failures (never double-counted)."""
        return self.persist_failures + self.detection_failures

    def _inc(self, name: str, n: int = 1):
        with self._counter_lock:
            setattr(self, name, getattr(self, name) + n)

    # ------------------------------------------------------------------
    # Model lifecycle
    # ------------------------------------------------------------------
    def reload_model(self) -> bool:
        """Load the TrustLab bundle and verify its schema + threshold. There is no fallback model."""
        self.model_loaded = False
        if not os.path.isfile(self.bundle_path):
            self.model_load_error = f"TrustLab bundle not found at {self.bundle_path}."
            return False
        try:
            with open(self.bundle_path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            model = TrustLabKitNET()
            model.load_bundle(self.bundle_path)
            if len(model.feature_names) != Config.TRUSTLAB_EXPECTED_FEATURES:
                raise ValueError(f"bundle has {len(model.feature_names)} features, "
                                 f"expected {Config.TRUSTLAB_EXPECTED_FEATURES}")
            if model.threshold != Config.TRUSTLAB_EXPECTED_THRESHOLD:
                raise ValueError(f"bundle threshold {model.threshold!r} != expected "
                                 f"{Config.TRUSTLAB_EXPECTED_THRESHOLD!r}")
            missing = [n for n in model.feature_names if n not in model.medians]
            if missing:
                raise ValueError(f"bundle has no median for {missing}")
        except Exception as exc:
            log.error("[EventProcessor] TrustLab bundle refused: %s", exc)
            self.model_load_error = f"TrustLab bundle could not be loaded: {exc}"
            return False
        self.kitnet = model
        self.feature_names = list(model.feature_names)
        self.medians = dict(model.medians)
        self.threshold = float(model.threshold)
        self.bundle_sha256 = digest
        self.model_loaded = True
        self.model_load_error = None
        return True

    def set_active_model_version(self, version_id: int):
        self._active_model_version_id = version_id

    @property
    def detector_enabled(self) -> bool:
        return self.detector_backend not in ("none", "disabled", "off", "")

    def detector_status(self) -> Dict[str, Any]:
        if not self.detector_enabled:
            state, reason = "disabled", f"DETECTOR_BACKEND={self.detector_backend!r}: inference is switched off."
        elif self.detector_backend != "kitnet_trustlab":
            state, reason = "unavailable", (f"DETECTOR_BACKEND={self.detector_backend!r} is not supported; the final "
                                            "pipeline runs only the TrustLab bundle (kitnet_trustlab).")
        elif not self.model_loaded:
            state, reason = "unavailable", self.model_load_error or MODEL_NOT_LOADED
        else:
            state, reason = "ready", None
        return {
            "state": state,
            "available": state == "ready",
            "backend": self.detector_backend,
            "model": MODEL_NAME,
            "final_model": True,
            "description": ("Authoritative pre-trained TrustLab KitNET bundle (28 dA ensemble + output dA), loaded "
                            "read-only from ml/kitnet_trustlab_bundle.pkl; never retrained by this backend."),
            "input_schema": DETECTOR_INPUT_SCHEMA,
            "input_dimension": len(self.feature_names) or Config.TRUSTLAB_EXPECTED_FEATURES,
            "anomaly_threshold": self.threshold,
            "bundle_sha256": self.bundle_sha256,
            "accepted_event_types": list(DETECTOR_ACCEPTED_TYPES),
            "rule_event_types": list(RULE_EVENT_TYPES),
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Real-time pub/sub (SSE consumers)
    # ------------------------------------------------------------------
    def subscribe(self, max_subscribers: Optional[int] = None) -> Optional[queue.Queue]:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._sub_lock:
            if max_subscribers is not None and len(self._subscribers) >= max_subscribers:
                return None
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    @property
    def subscriber_count(self) -> int:
        with self._sub_lock:
            return len(self._subscribers)

    def broadcast(self, msg_type: str, data: Dict[str, Any]):
        """Send a typed message {"id", "type", "ts", "data"} to every subscriber."""
        with self._sub_lock:
            self._seq += 1
            payload = {"id": self._seq, "type": msg_type, "ts": datetime.now(timezone.utc).isoformat(), "data": data}
            stale = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    stale.append(q)  # a client that stopped reading is dropped, not buffered forever
            for q in stale:
                self._subscribers.remove(q)

    # Back-compat for callers of the old untyped broadcast.
    def _broadcast(self, payload: Dict[str, Any]):
        self.broadcast("event", payload)

    # ------------------------------------------------------------------
    # Normalisation of heterogeneous network field names
    # ------------------------------------------------------------------
    @staticmethod
    def _norm(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise heterogeneous field names from BoT-IoT, CIC-IDS, UNSW-NB15, Zeek into a canonical dict."""
        def _get_field(keys: list, default: Any = None) -> Any:
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
            # Case-insensitive fallback
            raw_lower = {str(k).strip().lower(): v for k, v in raw.items()}
            for k in keys:
                kl = str(k).strip().lower()
                if kl in raw_lower and raw_lower[kl] is not None:
                    return raw_lower[kl]
            return default

        ts_raw = _get_field(["timestamp", "stime", "ts", "time", "date"], 0.0)
        try:
            ts_val = float(ts_raw)
        except (ValueError, TypeError):
            ts_val = 0.0

        src_ip = str(_get_field(["src_ip", "saddr", "srcip", "source ip", "id.orig_h", "ipv4_src_addr", "src ip"], "0.0.0.0"))
        dst_ip = str(_get_field(["dst_ip", "daddr", "dstip", "destination ip", "id.resp_h", "ipv4_dst_addr", "dst ip"], "0.0.0.0"))

        try:
            src_port = int(_get_field(["src_port", "sport", "source port", "id.orig_p", "l4_src_port", "src port"], 0))
        except (ValueError, TypeError):
            src_port = 0

        try:
            dst_port = int(_get_field(["dst_port", "dport", "dsport", "destination port", "id.resp_p", "l4_dst_port", "dst port"], 0))
        except (ValueError, TypeError):
            dst_port = 0

        proto = str(_get_field(["protocol", "proto"], "tcp")).upper()

        bytes_raw = _get_field(["bytes", "length", "sbytes", "orig_bytes", "total length of fwd packets", "totlen", "in_bytes", "tot_bytes"], 0)
        try:
            bytes_val = int(float(bytes_raw))
        except (ValueError, TypeError):
            bytes_val = 0

        pkts_raw = _get_field(["pkts", "packet_count", "spkts", "total fwd packets", "in_pkts", "tot_pkts"], 1)
        try:
            pkts_val = int(float(pkts_raw))
        except (ValueError, TypeError):
            pkts_val = 1

        dur_raw = _get_field(["duration", "dur", "flow_duration", "flow duration"], 0.0)
        try:
            dur_val = float(dur_raw)
        except (ValueError, TypeError):
            dur_val = 0.0

        return {
            "timestamp": ts_val,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  proto,
            "bytes":     bytes_val,
            "pkts":      pkts_val,
            "duration":  dur_val,
        }

    @staticmethod
    def _event_time(ts: float) -> datetime:
        if ts and ts > 0:
            try:
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                pass
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def ingest(self, raw_event: Dict[str, Any], source: str = SOURCE_API) -> Dict[str, Any]:
        """Externally supplied network record (POST /api/v1/events, dataset replay)."""
        return self.submit(raw_event, event_type=EVENT_NETWORK_RECORD, source=source)

    def ingest_batch(self, events: list[Dict[str, Any]], limit: int = 500, source: str = SOURCE_API) -> Dict[str, Any]:
        results = []
        threats = 0
        errors = 0
        for ev in events[:limit]:
            r = self.ingest(ev, source=source)
            results.append(r)
            if r.get("alert"):
                threats += 1
            if r.get("_warning") or r.get("error"):
                errors += 1
        return {
            "total_processed": len(results),
            "threats_detected": threats,
            "errors": errors,
            "results": results,
        }

    def submit(
        self,
        raw: Dict[str, Any],
        event_type: str,
        source: str,
        dedup_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process one network event (packet, flow or record). Returns the stored event
        (to_dict) plus `alert` / `hybrid_risk` / `risk_eval` / `_warning`, or {"error": …}
        when nothing was stored.
        """
        if event_type not in NETWORK_EVENT_TYPES:
            self._inc("events_rejected")
            return {"error": f"Unsupported network event_type '{event_type}'."}
        if not isinstance(raw, dict):
            self._inc("events_rejected")
            return {"error": "Event must be a JSON object."}
        norm = self._norm(raw)
        details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
        if raw.get("tls") and isinstance(raw["tls"], dict):
            details = {**details, "tls": raw["tls"]}
        for k in ("tcp_flags", "payload_bytes", "ip_version"):
            if raw.get(k) is not None:
                details[k] = raw[k]

        row = Event(
            event_uuid=f"EVT-{uuid.uuid4().hex[:12].upper()}",
            event_time=self._event_time(norm["timestamp"]),
            event_type=event_type,
            source=source,
            dedup_key=dedup_key,
            src_ip=norm["src_ip"],
            dst_ip=norm["dst_ip"],
            src_port=norm["src_port"] if raw.get("src_port") is not None or event_type == EVENT_NETWORK_RECORD else None,
            dst_port=norm["dst_port"] if raw.get("dst_port") is not None or event_type == EVENT_NETWORK_RECORD else None,
            protocol=norm["protocol"],
            bytes_transferred=norm["bytes"],
            packet_count=norm["pkts"],
            flow_duration=norm["duration"],
            flow_id=raw.get("flow_id"),
            direction=raw.get("direction"),
            details_json=json.dumps(details, default=str) if details else None,
            # Records keep the verbatim payload for re-processing; capture events are already
            # fully represented by their columns + details (no packet bytes exist to keep).
            raw_event_json=json.dumps(raw, default=str) if event_type == EVENT_NETWORK_RECORD else None,
            ai_processed=False,
        )
        self._pre_detection_status(row)
        return self._process(row, norm)

    def record_application_activity(
        self,
        *,
        activity_id: int,
        user_id: int,
        action: str,
        outcome: str,
        occurred_at: Optional[datetime],
        client_ip: Optional[str],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Application evidence for one portal file operation (FileActivity row `activity_id`).
        Identity comes from the server-side session, never from client input. The event is
        contextual evidence only: it is never converted into a model feature vector, but the
        application rule detectors (D13–D16, D27, D4, D24) evaluate it.
        """
        if not user_id or not action or not outcome:
            self._inc("events_rejected")
            return {"error": "Application activity requires user_id, action and outcome."}
        row = Event(
            event_uuid=f"EVT-{uuid.uuid4().hex[:12].upper()}",
            event_time=occurred_at or datetime.now(timezone.utc),
            event_type=EVENT_APPLICATION,
            source=SOURCE_APPLICATION,
            dedup_key=f"file_activity:{activity_id}",
            user_id=user_id,
            action=action,
            outcome=outcome,
            src_ip=client_ip,
            dst_ip=None,
            protocol=None,
            bytes_transferred=int(context.get("size_bytes") or 0),
            packet_count=None,
            flow_duration=None,
            details_json=json.dumps({"file_activity_id": activity_id, **context}, default=str),
            ai_processed=False,
            detection_status=DETECTION_NOT_APPLICABLE,
        )
        return self._process(row, None)

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------
    def _pre_detection_status(self, row: Event):
        """Decide before persisting whether the detector can evaluate this event."""
        if not self.detector_enabled:
            row.detection_status = DETECTION_UNAVAILABLE
            row.ai_error = f"Detector disabled (DETECTOR_BACKEND={self.detector_backend}) — event was not evaluated."
        elif row.event_type not in DETECTOR_ACCEPTED_TYPES:
            row.detection_status = DETECTION_UNSUPPORTED
        elif self.detector_backend != "kitnet_trustlab" or not self.model_loaded:
            row.detection_status = DETECTION_UNAVAILABLE
            row.ai_error = self.detector_status()["reason"] or MODEL_NOT_LOADED
        else:
            row.detection_status = DETECTION_PENDING

    def _existing(self, dedup_key: Optional[str]) -> Optional[Event]:
        if not dedup_key:
            return None
        return Event.query.filter_by(dedup_key=dedup_key).first()

    def _process(self, row: Event, norm: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        self._inc("events_received")

        # 1. Idempotency ------------------------------------------------------
        dup = self._existing(row.dedup_key)
        if dup is not None:
            self._inc("events_duplicate")
            return {**dup.to_dict(), "duplicate": True}

        # 2. Persist FIRST ----------------------------------------------------
        try:
            db.session.add(row)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            dup = self._existing(row.dedup_key)  # lost a race with an identical submission
            if dup is not None:
                self._inc("events_duplicate")
                return {**dup.to_dict(), "duplicate": True}
            self._inc("persist_failures")
            log.error("[EventProcessor] event could not be stored: %s", exc)
            return {"error": "Event could not be stored (database error).", "ai_processed": False, "anomaly_score": None}
        self._inc("events_ingested")

        # 3. AI detection (only when it can genuinely run) ---------------------
        if row.detection_status == DETECTION_PENDING:
            model = self._detect(row, norm)
        else:
            if row.detection_status == DETECTION_UNAVAILABLE:
                self._inc("detection_unavailable")
            elif row.detection_status == DETECTION_UNSUPPORTED:
                self._inc("detection_unsupported")
            model = self._model_not_run(row)

        # 4. Rule detection (D1–D28) -------------------------------------------
        rules = self._run_rules(row, model)

        # 5-6. Hybrid decision → alert, device; a failure here never removes the stored event
        hybrid = None
        alert_dict = None
        downstream_errors = []
        try:
            if row.event_type != EVENT_NETWORK_PACKET:
                hybrid = hybrid_risk(model, rules)
                row.hybrid_risk_json = json.dumps(hybrid, default=str)
            if hybrid and hybrid["alert"]:
                alert_dict = self._create_alert(row, rules, hybrid)
            if row.event_type in TRAFFIC_EVENT_TYPES or alert_dict:
                self._upsert_device(row, hybrid, bool(alert_dict), count_traffic=row.event_type in TRAFFIC_EVENT_TYPES)
            db.session.commit()
            if alert_dict:
                self._inc("alerts_created")
        except Exception as exc:
            db.session.rollback()
            alert_dict = None
            downstream_errors.append(f"Alert/device update failed ({type(exc).__name__}).")
            log.exception("[EventProcessor] alert/device stage failed for %s", row.event_uuid)

        # 7. Correlation ---------------------------------------------------------
        if row.event_type in (EVENT_APPLICATION, EVENT_NETWORK_FLOW):
            try:
                from services.correlation import evaluate_application_event, evaluate_network_flow
                if row.event_type == EVENT_APPLICATION:
                    links = evaluate_application_event(row)
                else:
                    evaluate_network_flow(row)
                    links = []
                db.session.commit()
                for link in links:
                    self.broadcast("correlation", link.to_dict())
            except Exception as exc:
                db.session.rollback()
                downstream_errors.append(f"Correlation failed ({type(exc).__name__}).")
                log.exception("[EventProcessor] correlation stage failed for %s", row.event_uuid)

        if rules.get("status") == "failed":
            downstream_errors.append(rules["reason"] + ".")
        try:
            row.processing_status = PROCESSING_DOWNSTREAM_ERROR if downstream_errors else PROCESSING_COMPLETE
            row.processing_error = " ".join(downstream_errors) or None
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("[EventProcessor] could not record processing status for %s", row.event_uuid)
        if downstream_errors:
            self._inc("downstream_failures")

        # 8. Response + broadcast ------------------------------------------------
        result = row.to_dict()
        result["alert"] = alert_dict
        result["hybrid_risk"] = hybrid
        result["risk_eval"] = {
            "severity":          hybrid["final_risk_level"],
            "risk_score":        hybrid["final_risk_score"],
            "anomaly_score":     hybrid["anomaly_score"],
            "anomaly_threshold": hybrid["anomaly_threshold"],
            "is_anomalous":      hybrid["is_anomalous"],
            "rule_score":        hybrid["rule_score"],
            "is_threat":         hybrid["alert"],
            "detection_source":  hybrid["detection_source"],
        } if hybrid else None
        result["explanation"] = hybrid["explanation"] if hybrid else None
        if row.detection_status in (DETECTION_UNAVAILABLE, DETECTION_FAILED) or                 (row.detection_status == DETECTION_UNSUPPORTED and row.ai_error):
            result["_warning"] = row.ai_error

        if row.event_type != EVENT_NETWORK_PACKET:  # packets surface through their flow + collector status
            self.broadcast("event", self.summary(row))
        if alert_dict:
            self.broadcast("alert", alert_dict)
        return result

    # ------------------------------------------------------------------
    # Stage 3: TrustLab KitNET
    # ------------------------------------------------------------------
    @staticmethod
    def _model_not_run(row: Event) -> Dict[str, Any]:
        reason = row.ai_error
        if not reason and row.detection_status == DETECTION_UNSUPPORTED:
            reason = ("packet events are scored through their completed flow" if row.event_type == EVENT_NETWORK_PACKET
                      else f"{row.event_type} events are not model inputs")
        if not reason and row.detection_status == DETECTION_NOT_APPLICABLE:
            reason = "application evidence is never converted into a model feature vector"
        return {"status": row.detection_status, "anomaly_score": None, "threshold": None,
                "is_anomalous": None, "reason": reason}

    def _feature_vector(self, row: Event, norm: Optional[Dict[str, Any]]):
        details = row.details
        raw = None
        if row.event_type == EVENT_NETWORK_FLOW:
            start = details.get("start_time")
        else:
            # A record without its own timestamp has no observed time: the time features are imputed.
            start = norm["timestamp"] if norm and norm.get("timestamp", 0) > 0 else None
            try:
                raw = json.loads(row.raw_event_json) if row.raw_event_json else None
            except ValueError:
                raw = None
        columns = {"src_port": row.src_port, "dst_port": row.dst_port, "protocol": row.protocol,
                   "duration": row.flow_duration, "timestamp": start}
        return build_feature_vector(event_type=row.event_type, columns=columns, details=details, raw_record=raw,
                                    feature_names=self.feature_names, medians=self.medians,
                                    tz_name=Config.TRUSTLAB_TIMEZONE)

    def _detect(self, row: Event, norm: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Canonical 78-feature vector → TrustLab KitNET → anomaly result. Records the outcome on the row."""
        import numpy as np
        model: Dict[str, Any] = {"status": DETECTION_FAILED, "anomaly_score": None, "threshold": self.threshold,
                                 "is_anomalous": None, "reason": None}
        try:
            fv = self._feature_vector(row, norm)
            coverage = fv.coverage()
            measured = sum(1 for n in fv.names if n not in _NON_MEASUREMENT and fv.sources[n] in (OBSERVED, ZERO))
            coverage["measured_flow_features"] = measured
            model["feature_coverage"] = coverage
            if measured < Config.TRUSTLAB_MIN_MEASURED_FEATURES:
                row.detection_status = DETECTION_UNSUPPORTED
                row.ai_processed = False
                row.anomaly_score = None
                row.ai_error = (f"Only {measured} of 74 flow features were measured (minimum "
                                f"{Config.TRUSTLAB_MIN_MEASURED_FEATURES}); not scored on training medians.")
                model.update(status=DETECTION_UNSUPPORTED, reason=row.ai_error)
                self._inc("detection_unsupported")
            else:
                with self._detect_lock:
                    score, errors = self.kitnet.score(fv.values)
                score = float(score)
                if not np.isfinite(score):
                    raise ValueError("model returned a non-finite score")
                errors = np.nan_to_num(np.asarray(errors, dtype=np.float64), nan=0.0)
                total = float(errors.sum()) or 1.0
                top = []
                for i in np.argsort(errors)[::-1][:5]:
                    name, src = fv.names[i], fv.sources[fv.names[i]]
                    share = 100.0 * float(errors[i]) / total
                    top.append({
                        "feature_name": name, "display_name": name,
                        "contribution_pct": round(share, 2),
                        "reconstruction_error": round(float(errors[i]), 6),
                        "input_value": round(float(fv.values[i]), 6),
                        "training_median": self.medians.get(name),
                        "value_source": src,
                        "description": (f"{name} = {float(fv.values[i]):.6g} "
                                        f"({'bundle median, not measured' if src == IMPUTED else src}); "
                                        f"{share:.1f}% of the reconstruction error."),
                    })
                model.update(status=DETECTION_SCORED, anomaly_score=score, threshold=self.threshold,
                             is_anomalous=score > self.threshold, top_features=top)
                row.feature_vector_json = json.dumps({
                    "schema": DETECTOR_INPUT_SCHEMA, "names": fv.names, "values": fv.values.tolist(),
                    "sources": fv.sources, "imputed_reasons": fv.reasons,
                })
                row.anomaly_score = score
                row.ai_processed = True
                row.ai_error = None
                row.detection_status = DETECTION_SCORED
                self._inc("events_evaluated")
        except Exception as exc:
            log.exception("[EventProcessor] detector failed for %s", row.event_uuid)
            row.anomaly_score = None
            row.ai_processed = False
            row.ai_error = f"AI pipeline error: {type(exc).__name__}"
            row.detection_status = DETECTION_FAILED
            model.update(status=DETECTION_FAILED, anomaly_score=None, is_anomalous=None, reason=row.ai_error)
            self._inc("detection_failures")
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("[EventProcessor] could not store detection result for %s", row.event_uuid)
            model.update(status=DETECTION_FAILED, anomaly_score=None, is_anomalous=None,
                         reason="detection result could not be stored")
        return model

    # ------------------------------------------------------------------
    # Stage 4: rule detectors (D1–D28)
    # ------------------------------------------------------------------
    def _run_rules(self, row: Event, model: Dict[str, Any]) -> Dict[str, Any]:
        if row.event_type not in RULE_EVENT_TYPES:
            return {"status": "skipped", "reason": "packet events are evaluated through their completed flow"}
        from services.detection.engine import DetectionEngine, cfg as detection_cfg
        if not detection_cfg("DETECTION_ENABLED"):
            return {"status": "disabled", "reason": "DETECTION_ENABLED is off"}
        try:
            out = DetectionEngine.get_instance().run(row, create_alert=False,
                                                     flagged_hint=bool(model.get("is_anomalous")))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            self._inc("rule_failures")
            log.exception("[EventProcessor] rule detection failed for %s", row.event_uuid)
            return {"status": "failed", "reason": f"DetectionEngine error ({type(exc).__name__})"}
        if out is None:
            return {"status": "disabled", "reason": "rule engine did not evaluate this event"}
        if out.get("skipped"):
            return {"status": "skipped", "reason": out["skipped"],
                    "summary": json.loads(row.detection_summary_json or "{}")}
        self._inc("rule_evaluations")
        combined = out.get("combined") or {}
        return {"status": "evaluated", "summary": out["summary"], "triggered": out["triggered"],
                "signal_rows": out["signal_rows"], "rule_score": combined.get("rule_score"),
                "rule_severity": combined.get("severity"), "alert_due": out["alert_due"]}

    # ------------------------------------------------------------------
    # Stage 5: one alert per event (AI, rules or hybrid)
    # ------------------------------------------------------------------
    def _create_alert(self, row: Event, rules: Dict[str, Any], hybrid: Dict[str, Any]) -> Dict[str, Any]:
        from services.detection.base import SEVERITY_ORDER
        from services.detection.engine import _mitigation
        security = [t for t in hybrid["triggered_detectors"] if t.get("category", "security") == "security"]
        entries = [{"detector_id": t["detector_id"], "name": t["name"], "severity": t["severity"], "score": t["score"],
                    "reason": t["reason"], "evidence": t.get("evidence") or [], "signal_id": t.get("signal_id")}
                   for t in security]
        details = row.details
        severity = hybrid["final_risk_level"]
        if hybrid["rule_alert_due"]:
            # A HIGH/CRITICAL rule signal is never reported below its own severity.
            top_rule = max((SEVERITY_ORDER.get(t["severity"], 0) for t in security), default=0)
            if top_rule > SEVERITY_ORDER.get(severity, 0):
                severity = next(k for k, v in SEVERITY_ORDER.items() if v == top_rule)
        risk_factors = []
        if hybrid["anomaly_score"] is not None:
            risk_factors.append(f"KitNET anomaly score {hybrid['anomaly_score']:.6f} "
                                f"{'exceeds' if hybrid['is_anomalous'] else 'is below'} the trained threshold "
                                f"{hybrid['anomaly_threshold']:.6f}")
        mitigation = _mitigation(entries) if entries else [
            "Review the flow's top reconstruction-error features against normal traffic for this host."]
        if hybrid["is_anomalous"]:
            mitigation.insert(0, "Inspect the KitNET top contributing features; note which were measured and which imputed.")
        outbound = details.get("outbound_bytes")
        alert_row = Alert(
            alert_uuid=f"ALT-{uuid.uuid4().hex[:10].upper()}",
            severity=severity,
            risk_score=hybrid["final_risk_score"] or 0.0,
            anomaly_score=hybrid["anomaly_score"],
            z_score=None, confidence=None,           # the bundle provides no calibrated z-score / confidence
            detection_source=hybrid["detection_source"],
            rule_score=hybrid["rule_score"],
            rule_signals_json=json.dumps(entries, default=str),
            signal_count=len(entries),
            hybrid_risk_json=json.dumps(hybrid, default=str),
            event_type=row.event_type,
            entity_key=row.entity_key,
            user_id=row.user_id if row.event_type == EVENT_APPLICATION else None,
            src_ip=row.src_ip, dst_ip=row.dst_ip, src_port=row.src_port, dst_port=row.dst_port,
            protocol=row.protocol,
            bytes_transferred=int(outbound if outbound is not None else (row.bytes_transferred or 0)),
            source=row.source,
            off_hours=any(t["detector_id"] == "D4" for t in security),
            is_external_dst=bool(details.get("external_ip")) or row.direction == "outbound",
            evidence_json=json.dumps(hybrid["top_features"] if hybrid["is_anomalous"] else [], default=str),
            explanation=hybrid["explanation"],
            mitigation_json=json.dumps(mitigation),
            risk_factors_json=json.dumps(risk_factors),
            status="open",
            model_version_id=self._active_model_version_id if hybrid["anomaly_score"] is not None else None,
        )
        db.session.add(alert_row)
        db.session.flush()
        row.alert_id = alert_row.id
        for sig in rules.get("signal_rows") or []:
            if sig.status == "triggered":
                sig.alert_id = alert_row.id
        if row.detection_summary_json:
            summ = json.loads(row.detection_summary_json)
            summ["alert_created"] = True
            summ["alert_id"] = alert_row.alert_uuid
            row.detection_summary_json = json.dumps(summ, default=str)
        return alert_row.to_dict()

    @staticmethod
    def summary(row: Event) -> Dict[str, Any]:
        """Compact event shape for the live stream (no raw payloads or feature vectors)."""
        d = row.to_dict()
        d.pop("details", None)
        return d

    # ------------------------------------------------------------------
    # Device upsert
    # ------------------------------------------------------------------
    def _upsert_device(self, row: Event, hybrid: Optional[Dict], is_threat: bool, count_traffic: bool = True):
        dev_id = row.src_ip
        if not dev_id:
            return
        device = Device.query.filter_by(device_id=dev_id).first()
        now = datetime.now(timezone.utc)
        bytes_val = (row.bytes_transferred or 0) if count_traffic else 0

        if device is None:
            device = Device(
                device_id=dev_id,
                hostname=f"ws-{dev_id.split('.')[-1]}",
                risk_score=0.0,
                alert_count=0,
                event_count=1 if count_traffic else 0,
                total_bytes_out=bytes_val,
                is_flagged=False,
                first_seen=now,
                last_seen=now,
            )
            db.session.add(device)
        else:
            if count_traffic:
                device.event_count = (device.event_count or 0) + 1
                device.total_bytes_out = (device.total_bytes_out or 0) + bytes_val
            device.last_seen = now

        if is_threat and hybrid:
            current_risk = device.risk_score or 0.0
            device.risk_score = max(current_risk, hybrid["final_risk_score"] or 0.0)
            device.alert_count = (device.alert_count or 0) + 1
            device.last_alert_at = now
            if hybrid["final_risk_level"] in ("HIGH", "CRITICAL"):
                device.is_flagged = True

    # ------------------------------------------------------------------
    # Counters snapshot
    # ------------------------------------------------------------------
    def counters(self) -> Dict[str, int]:
        with self._counter_lock:
            return {
                "events_received": self.events_received,
                "events_rejected": self.events_rejected,
                "events_ingested": self.events_ingested,
                "events_duplicate": self.events_duplicate,
                "persist_failures": self.persist_failures,
                "events_evaluated": self.events_evaluated,
                "detection_unavailable": self.detection_unavailable,
                "detection_unsupported": self.detection_unsupported,
                "detection_failures": self.detection_failures,
                "rule_evaluations": self.rule_evaluations,
                "rule_failures": self.rule_failures,
                "downstream_failures": self.downstream_failures,
                "alerts_created": self.alerts_created,
            }


def event_type_is_valid(value: str) -> bool:
    return value in EVENT_TYPES
