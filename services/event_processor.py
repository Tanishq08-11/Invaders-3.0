"""
Event Processor — the single integration seam between raw ingestion and AI.
=============================================================================
Responsible for:
  1. Persisting every incoming event *before* the detector runs.
  2. Calling the detector module (AfterImage → KitNET → RiskEngine → XAI).
  3. Recording AI failures on the event row without assigning a silent zero.
  4. Creating an Alert row only when the detector says "threat".
  5. Updating the Device profile.
  6. Broadcasting the result to any connected real-time listeners.
"""
from typing import Dict, Any, Optional, Tuple
import json
import uuid
import traceback
from datetime import datetime, timezone
import queue
import threading
import os
import numpy as np

from config import Config
from core.database import db
from core.models import Event, Alert, Device, ModelVersion, AnalystAction
from extractor.afterimage import AfterImage
from ml.kitnet import KitNET
from ml.risk_engine import RiskEngine
from ml.explanation_engine import ExplanationEngine


class EventProcessor:
    """Singleton that owns the AI pipeline and processes events."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self, checkpoint_path: Optional[str] = None):
        self.checkpoint_path = checkpoint_path or os.path.join(
            Config.CHECKPOINTS_DIR, "kitnet_baseline.pkl"
        )

        # --- AI pipeline components (Person 1-3's work, imported not duplicated) ---
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

        self.model_loaded = False
        self._active_model_version_id: Optional[int] = None

        # SSE / WebSocket subscriber queues
        self._subscribers: list[queue.Queue] = []
        self._sub_lock = threading.Lock()

        # Counters for /metrics
        self.events_ingested = 0
        self.events_evaluated = 0
        self.events_failed = 0
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

    # ------------------------------------------------------------------
    # Model lifecycle
    # ------------------------------------------------------------------
    def reload_model(self) -> bool:
        if os.path.exists(self.checkpoint_path):
            try:
                self.kitnet.load(self.checkpoint_path)
                self.model_loaded = True
                return True
            except Exception as exc:
                print(f"[EventProcessor] model load failed: {exc}")
                self.model_loaded = False
        return False

    def set_active_model_version(self, version_id: int):
        self._active_model_version_id = version_id

    # ------------------------------------------------------------------
    # Real-time pub/sub (SSE / polling consumers)
    # ------------------------------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, payload: Dict[str, Any]):
        with self._sub_lock:
            stale = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    stale.append(q)
            for q in stale:
                self._subscribers.remove(q)

    # ------------------------------------------------------------------
    # Helpers to normalise incoming payloads (BoT-IoT column names, etc.)
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

    # ------------------------------------------------------------------
    # CORE: ingest a single event
    # ------------------------------------------------------------------
    def ingest(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full pipeline for ONE event:
          persist → extract → score → risk → explain → alert → device → broadcast
        Returns a result dict suitable for the API response.
        """
        self.events_ingested += 1
        norm = self._norm(raw_event)

        # 1. Persist the raw event FIRST ----------------------------------
        evt_uuid = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        evt_ts = None
        if norm["timestamp"] > 0:
            try:
                evt_ts = datetime.fromtimestamp(norm["timestamp"], tz=timezone.utc)
            except Exception:
                evt_ts = datetime.now(timezone.utc)
        else:
            evt_ts = datetime.now(timezone.utc)

        event_row = Event(
            event_uuid=evt_uuid,
            event_time=evt_ts,
            src_ip=norm["src_ip"],
            dst_ip=norm["dst_ip"],
            src_port=norm["src_port"],
            dst_port=norm["dst_port"],
            protocol=norm["protocol"],
            bytes_transferred=norm["bytes"],
            packet_count=norm["pkts"],
            flow_duration=norm["duration"],
            raw_event_json=json.dumps(raw_event, default=str),
            ai_processed=False,
            ai_error=None,
            anomaly_score=None,
        )
        try:
            db.session.add(event_row)
            db.session.flush()  # get event_row.id before we might need it
        except Exception as db_exc:
            db.session.rollback()
            self.events_failed += 1
            return {
                "error": f"Database write error: {str(db_exc)}",
                "ai_processed": False,
                "anomaly_score": None
            }

        # 2. Run the AI pipeline -----------------------------------------
        anomaly_score = None
        feat_errors = None
        risk_eval = None
        explanation_data = None
        ai_error_msg = None

        if not self.model_loaded:
            ai_error_msg = "Model not loaded — event was not evaluated."
            self.events_failed += 1
        else:
            try:
                # AfterImage feature extraction (zero decryption)
                feat_vec = self.extractor.extract_from_flow(norm)
                event_row.feature_vector_json = json.dumps(feat_vec.tolist())

                # KitNET anomaly scoring
                anomaly_score, feat_errors = self.kitnet.score(feat_vec)
                event_row.anomaly_score = float(anomaly_score)

                # Risk Engine contextual evaluation
                risk_eval = self.risk_engine.evaluate(
                    anomaly_score=anomaly_score,
                    flow_meta=norm,
                    baseline_mean=self.kitnet.baseline_mean,
                    baseline_std=self.kitnet.baseline_std,
                    baseline_max=self.kitnet.baseline_max,
                )

                # XAI explanation (only when non-NORMAL)
                if risk_eval["severity"] != "NORMAL":
                    explanation_data = self.explanation_engine.explain(
                        feature_errors=feat_errors,
                        flow_meta=norm,
                        risk_evaluation=risk_eval,
                    )

                event_row.ai_processed = True
                self.events_evaluated += 1

            except Exception as exc:
                ai_error_msg = f"AI pipeline error: {traceback.format_exc()}"
                self.events_failed += 1

        if ai_error_msg:
            event_row.ai_error = ai_error_msg
            event_row.anomaly_score = None
            event_row.ai_processed = False
            # Commit the event with the error recorded — do NOT assign zero score
            db.session.commit()
            result = event_row.to_dict()
            result["alert"] = None
            result["_warning"] = ai_error_msg
            self._broadcast(result)
            return result

        # 3. Create Alert if threat ----------------------------------------
        alert_dict = None
        is_threat = risk_eval and risk_eval.get("is_threat", False)

        if is_threat and explanation_data:
            alert_uuid = f"ALT-{uuid.uuid4().hex[:10].upper()}"
            alert_row = Alert(
                alert_uuid=alert_uuid,
                severity=risk_eval["severity"],
                risk_score=risk_eval["risk_score"],
                anomaly_score=anomaly_score,
                z_score=risk_eval["z_score"],
                confidence=risk_eval["confidence"],
                src_ip=norm["src_ip"],
                dst_ip=norm["dst_ip"],
                src_port=norm["src_port"],
                dst_port=norm["dst_port"],
                protocol=norm["protocol"],
                bytes_transferred=norm["bytes"],
                off_hours=risk_eval.get("off_hours", False),
                is_external_dst=risk_eval.get("is_external_dst", False),
                evidence_json=json.dumps(explanation_data["top_features"]),
                explanation=explanation_data["explanation_text"],
                mitigation_json=json.dumps(explanation_data["mitigation_steps"]),
                risk_factors_json=json.dumps(risk_eval.get("risk_factors", [])),
                status="open",
                model_version_id=self._active_model_version_id,
            )
            db.session.add(alert_row)
            db.session.flush()

            event_row.alert_id = alert_row.id
            alert_dict = alert_row.to_dict()
            self.alerts_created += 1

        # 4. Upsert Device profile ----------------------------------------
        self._upsert_device(norm, risk_eval, is_threat)

        # 5. Commit everything atomically ---------------------------------
        try:
            db.session.commit()
        except Exception as db_exc:
            db.session.rollback()
            self.events_failed += 1
            return {
                "error": f"Database commit error: {str(db_exc)}",
                "ai_processed": False,
                "anomaly_score": None
            }

        # 6. Build response ------------------------------------------------
        result = event_row.to_dict()
        result["risk_eval"] = {
            "severity":    risk_eval["severity"],
            "risk_score":  round(risk_eval["risk_score"], 1),
            "z_score":     round(risk_eval["z_score"], 2),
            "confidence":  round(risk_eval["confidence"], 2),
            "is_threat":   is_threat,
            "off_hours":   risk_eval.get("off_hours", False),
            "is_external": risk_eval.get("is_external_dst", False),
        } if risk_eval else None
        result["alert"] = alert_dict
        result["explanation"] = explanation_data["explanation_text"] if explanation_data else None

        # 7. Broadcast to real-time listeners ------------------------------
        self._broadcast(result)
        return result

    # ------------------------------------------------------------------
    # Batch ingestion (wraps single ingest)
    # ------------------------------------------------------------------
    def ingest_batch(self, events: list[Dict[str, Any]], limit: int = 500) -> Dict[str, Any]:
        results = []
        threats = 0
        errors = 0
        for ev in events[:limit]:
            r = self.ingest(ev)
            results.append(r)
            if r.get("alert"):
                threats += 1
            if r.get("_warning"):
                errors += 1
        return {
            "total_processed": len(results),
            "threats_detected": threats,
            "errors": errors,
            "results": results,
        }

    # ------------------------------------------------------------------
    # Device upsert
    # ------------------------------------------------------------------
    def _upsert_device(self, norm: Dict, risk_eval: Optional[Dict], is_threat: bool):
        dev_id = norm["src_ip"]
        device = Device.query.filter_by(device_id=dev_id).first()
        now = datetime.now(timezone.utc)
        bytes_val = norm.get("bytes") or 0

        if device is None:
            device = Device(
                device_id=dev_id,
                hostname=f"ws-{dev_id.split('.')[-1]}",
                risk_score=0.0,
                alert_count=0,
                event_count=1,
                total_bytes_out=bytes_val,
                is_flagged=False,
                first_seen=now,
                last_seen=now,
            )
            db.session.add(device)
        else:
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
