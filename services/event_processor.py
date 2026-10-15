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
  3. detection, only when the active detector accepts this event type and is loaded
                                     → detection_status = scored | unavailable | unsupported | failed | not_applicable
  4. alert, only from a genuine detector result (RiskEngine on a real anomaly score)
  5. device profile update
  6. application ↔ network correlation (application events and completed flows)
                                     → processing_status = complete | downstream_error
  7. broadcast a typed message to SSE subscribers

No stage ever substitutes a score: when inference does not run the score stays NULL,
detection_status explains why, and no alert is created.
"""
from typing import Dict, Any, Optional
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
from extractor.afterimage import AfterImage
from ml.kitnet import KitNET
from ml.risk_engine import RiskEngine
from ml.explanation_engine import ExplanationEngine

log = logging.getLogger(__name__)

MODEL_NOT_LOADED = "Model not loaded — event was not evaluated."
# The existing AfterImage → KitNET path consumes per-packet / per-record metadata.
# Aggregated flows use a different (canonical) schema that no loaded model accepts yet.
DETECTOR_INPUT_SCHEMA = "afterimage-v1 (100 damped statistics over packet/record metadata)"
DETECTOR_ACCEPTED_TYPES = (EVENT_NETWORK_PACKET, EVENT_NETWORK_RECORD)


class EventValidationError(ValueError):
    """Input that cannot form a valid event; nothing is stored."""


class EventProcessor:
    """Singleton that owns the detector pipeline and processes every event."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self, checkpoint_path: Optional[str] = None):
        self.checkpoint_path = checkpoint_path or os.path.join(
            Config.CHECKPOINTS_DIR, "kitnet_baseline.pkl"
        )

        # --- Detector components (Person 1-3's work, imported not duplicated) ---
        self.extractor = AfterImage(lambdas=Config.AFTERIMAGE_LAMBDAS)
        self.kitnet = KitNET(
            input_dim=self.extractor.get_feature_dimension(),
            max_cluster_size=Config.KITNET_MAX_CLUSTER_SIZE,
            hidden_ratio=Config.KITNET_HIDDEN_RATIO,
            lr=Config.KITNET_LEARNING_RATE,
        )
        self.risk_engine = RiskEngine(
            z_low=Config.Z_THRESHOLD_LOW,
            z_med=Config.Z_THRESHOLD_MEDIUM,
            z_high=Config.Z_THRESHOLD_HIGH,
            z_crit=Config.Z_THRESHOLD_CRITICAL,
        )
        self.explanation_engine = ExplanationEngine(
            feature_names=self.extractor.get_feature_names()
        )

        self.detector_backend = Config.DETECTOR_BACKEND
        self.model_loaded = False
        self.model_load_error: Optional[str] = None
        self._active_model_version_id: Optional[int] = None
        # AfterImage keeps per-host state; requests and the collector worker share it.
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
        if os.path.exists(self.checkpoint_path):
            try:
                self.kitnet.load(self.checkpoint_path)
                self.model_loaded = True
                self.model_load_error = None
                return True
            except Exception as exc:
                log.error("[EventProcessor] model load failed: %s", exc)
                self.model_loaded = False
                self.model_load_error = f"Checkpoint could not be loaded ({type(exc).__name__})."
        else:
            self.model_load_error = "No model checkpoint found."
        return False

    def set_active_model_version(self, version_id: int):
        self._active_model_version_id = version_id

    @property
    def detector_enabled(self) -> bool:
        return self.detector_backend not in ("none", "disabled", "off", "")

    def detector_status(self) -> Dict[str, Any]:
        model_type = type(self.kitnet).__name__ if self.kitnet is not None else None
        if not self.detector_enabled:
            state, reason = "disabled", f"DETECTOR_BACKEND={self.detector_backend!r}: inference is switched off."
        elif not self.model_loaded:
            state, reason = "unavailable", self.model_load_error or MODEL_NOT_LOADED
        else:
            state, reason = "ready", None
        return {
            "state": state,
            "available": state == "ready",
            "backend": self.detector_backend,
            "model": "kitnet_baseline" if model_type == "KitNET" else model_type,
            # The teammate's final model is integrated separately; nothing here claims to be it.
            "final_model": False,
            "description": (
                "Bootstrap KitNET baseline trained by this backend on the bundled BoT-IoT normal "
                "sample — a prototype detector, not the final trained model."
                if model_type == "KitNET" else
                "Externally supplied model hot-swapped through services/model_adapter.py."
            ),
            "input_schema": DETECTOR_INPUT_SCHEMA,
            "accepted_event_types": list(DETECTOR_ACCEPTED_TYPES),
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
        (to_dict) plus `alert` / `risk_eval` / `_warning`, or {"error": …} when nothing was stored.
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
        contextual evidence only: it is never converted into a model feature vector.
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
        elif not self.model_loaded:
            row.detection_status = DETECTION_UNAVAILABLE
            row.ai_error = MODEL_NOT_LOADED
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

        # 3. Detection (only when it can genuinely run) ------------------------
        risk_eval = explanation = None
        if row.detection_status == DETECTION_PENDING:
            risk_eval, explanation = self._detect(row, norm)
        elif row.detection_status == DETECTION_UNAVAILABLE:
            self._inc("detection_unavailable")
        elif row.detection_status == DETECTION_UNSUPPORTED:
            self._inc("detection_unsupported")

        # 4-6. Downstream stages; a failure here never removes the stored event ----
        alert_dict = None
        downstream_errors = []
        try:
            is_threat = bool(risk_eval and risk_eval.get("is_threat"))
            if is_threat and explanation:
                alert_dict = self._create_alert(row, norm, risk_eval, explanation)
            if row.event_type in TRAFFIC_EVENT_TYPES or alert_dict:
                self._upsert_device(row, risk_eval, is_threat, count_traffic=row.event_type in TRAFFIC_EVENT_TYPES)
            db.session.commit()
            if alert_dict:
                self._inc("alerts_created")
        except Exception as exc:
            db.session.rollback()
            alert_dict = None
            downstream_errors.append(f"Alert/device update failed ({type(exc).__name__}).")
            log.exception("[EventProcessor] alert/device stage failed for %s", row.event_uuid)

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

        try:
            row.processing_status = PROCESSING_DOWNSTREAM_ERROR if downstream_errors else PROCESSING_COMPLETE
            row.processing_error = " ".join(downstream_errors) or None
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("[EventProcessor] could not record processing status for %s", row.event_uuid)
        if downstream_errors:
            self._inc("downstream_failures")

        # 7. Response + broadcast ------------------------------------------------
        result = row.to_dict()
        result["alert"] = alert_dict
        result["risk_eval"] = {
            "severity":    risk_eval["severity"],
            "risk_score":  round(risk_eval["risk_score"], 1),
            "z_score":     round(risk_eval["z_score"], 2),
            "confidence":  round(risk_eval["confidence"], 2),
            "is_threat":   bool(risk_eval.get("is_threat")),
            "off_hours":   risk_eval.get("off_hours", False),
            "is_external": risk_eval.get("is_external_dst", False),
        } if risk_eval else None
        result["explanation"] = explanation["explanation_text"] if explanation else None
        if row.detection_status in (DETECTION_UNAVAILABLE, DETECTION_FAILED):
            result["_warning"] = row.ai_error

        if row.event_type != EVENT_NETWORK_PACKET:  # packets surface through their flow + collector status
            self.broadcast("event", self.summary(row))
        if alert_dict:
            self.broadcast("alert", alert_dict)
        return result

    def _detect(self, row: Event, norm: Dict[str, Any]):
        """Run AfterImage → KitNET → RiskEngine → XAI. Records the outcome on the row."""
        risk_eval = explanation = None
        try:
            with self._detect_lock:
                feat_vec = self.extractor.extract_from_flow(norm)
                anomaly_score, feat_errors = self.kitnet.score(feat_vec)
            risk_eval = self.risk_engine.evaluate(
                anomaly_score=anomaly_score,
                flow_meta=norm,
                baseline_mean=self.kitnet.baseline_mean,
                baseline_std=self.kitnet.baseline_std,
                baseline_max=self.kitnet.baseline_max,
            )
            if risk_eval["severity"] != "NORMAL":
                explanation = self.explanation_engine.explain(
                    feature_errors=feat_errors, flow_meta=norm, risk_evaluation=risk_eval,
                )
            row.feature_vector_json = json.dumps(feat_vec.tolist())
            row.anomaly_score = float(anomaly_score)
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
            risk_eval = explanation = None
            self._inc("detection_failures")
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("[EventProcessor] could not store detection result for %s", row.event_uuid)
            risk_eval = explanation = None
        return risk_eval, explanation

    def _create_alert(self, row: Event, norm, risk_eval, explanation) -> Dict[str, Any]:
        alert_row = Alert(
            alert_uuid=f"ALT-{uuid.uuid4().hex[:10].upper()}",
            severity=risk_eval["severity"],
            risk_score=risk_eval["risk_score"],
            anomaly_score=row.anomaly_score,
            z_score=risk_eval["z_score"],
            confidence=risk_eval["confidence"],
            src_ip=norm["src_ip"],
            dst_ip=norm["dst_ip"],
            src_port=norm["src_port"],
            dst_port=norm["dst_port"],
            protocol=norm["protocol"],
            bytes_transferred=norm["bytes"],
            source=row.source,
            off_hours=risk_eval.get("off_hours", False),
            is_external_dst=risk_eval.get("is_external_dst", False),
            evidence_json=json.dumps(explanation["top_features"]),
            explanation=explanation["explanation_text"],
            mitigation_json=json.dumps(explanation["mitigation_steps"]),
            risk_factors_json=json.dumps(risk_eval.get("risk_factors", [])),
            status="open",
            model_version_id=self._active_model_version_id,
        )
        db.session.add(alert_row)
        db.session.flush()
        row.alert_id = alert_row.id
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
    def _upsert_device(self, row: Event, risk_eval: Optional[Dict], is_threat: bool, count_traffic: bool = True):
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

        if is_threat and risk_eval:
            current_risk = device.risk_score or 0.0
            device.risk_score = max(current_risk, risk_eval["risk_score"])
            device.alert_count = (device.alert_count or 0) + 1
            device.last_alert_at = now
            if risk_eval["severity"] in ("HIGH", "CRITICAL"):
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
                "downstream_failures": self.downstream_failures,
                "alerts_created": self.alerts_created,
            }


def event_type_is_valid(value: str) -> bool:
    return value in EVENT_TYPES
