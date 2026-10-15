"""
Detection Service for Real-Time Encrypted Traffic Insider Threat Detection
Coordinates:
AfterImage Feature Extractor -> KitNET Autoencoder Detector -> Alert & Risk Engine -> Explanation Engine
"""
from typing import Dict, Any, List, Optional
import os
import json
import uuid
from datetime import datetime, timezone
import queue
import threading
import numpy as np

from config import Config
from core.database import db
from core.models_db import Alert, FlowRecord, HostProfile
from extractor.afterimage import AfterImage
from ml.kitnet import KitNET
from ml.risk_engine import RiskEngine
from ml.explanation_engine import ExplanationEngine


class DetectionService:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, checkpoint_path: Optional[str] = None):
        self.checkpoint_path = checkpoint_path or os.path.join(
            Config.CHECKPOINTS_DIR, "kitnet_baseline.pkl"
        )
        self.extractor = AfterImage(lambdas=Config.AFTERIMAGE_LAMBDAS)
        self.kitnet = KitNET(
            input_dim=self.extractor.get_feature_dimension(),
            max_cluster_size=Config.KITNET_MAX_CLUSTER_SIZE,
            hidden_ratio=Config.KITNET_HIDDEN_RATIO,
            lr=Config.KITNET_LEARNING_RATE
        )
        self.risk_engine = RiskEngine(
            z_low=Config.Z_THRESHOLD_LOW,
            z_med=Config.Z_THRESHOLD_MEDIUM,
            z_high=Config.Z_THRESHOLD_HIGH,
            z_crit=Config.Z_THRESHOLD_CRITICAL
        )
        self.explanation_engine = ExplanationEngine(
            feature_names=self.extractor.get_feature_names()
        )

        self.is_model_loaded = False
        self.subscribers: List[queue.Queue] = []
        self._sub_lock = threading.Lock()

        # Attempt to load trained baseline checkpoint if exists
        self.reload_model()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def reload_model(self) -> bool:
        """Loads or reloads the trained KitNET baseline model from disk."""
        if os.path.exists(self.checkpoint_path):
            try:
                self.kitnet.load(self.checkpoint_path)
                self.is_model_loaded = True
                return True
            except Exception as e:
                print(f"[Warning] Failed to load model checkpoint: {e}")
                self.is_model_loaded = False
                return False
        return False

    def subscribe(self) -> queue.Queue:
        """Subscribes an SSE listener to real-time events."""
        q = queue.Queue(maxsize=100)
        with self._sub_lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Removes an SSE subscriber."""
        with self._sub_lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def _broadcast(self, event_data: Dict[str, Any]):
        """Dispatches an event to all connected SSE clients."""
        with self._sub_lock:
            for q in list(self.subscribers):
                try:
                    q.put_nowait(event_data)
                except queue.Full:
                    # Client is slow, remove to prevent memory leak
                    self.subscribers.remove(q)

    def process_flow(
        self,
        flow_meta: Dict[str, Any],
        persist: bool = True
    ) -> Dict[str, Any]:
        """
        Executes end-to-end detection pipeline on a single network flow or packet header.
        Does NOT decrypt contents.
        """
        # 1. Kitsune Feature Extraction
        feat_vector = self.extractor.extract_from_flow(flow_meta)

        # 2. KitNET Anomaly Scoring
        anomaly_score, feat_errors = self.kitnet.score(feat_vector)

        # 3. Alert / Risk Evaluation
        risk_eval = self.risk_engine.evaluate(
            anomaly_score=anomaly_score,
            flow_meta=flow_meta,
            baseline_mean=self.kitnet.baseline_mean,
            baseline_std=self.kitnet.baseline_std,
            baseline_max=self.kitnet.baseline_max
        )

        is_threat = risk_eval["is_threat"]
        explanation_data = None
        alert_obj = None

        # 4. Explanation Engine (if anomalous)
        if is_threat or risk_eval["severity"] != "NORMAL":
            explanation_data = self.explanation_engine.explain(
                feature_errors=feat_errors,
                flow_meta=flow_meta,
                risk_evaluation=risk_eval
            )

        # 5. Database Persistence (Alerts, Flow telemetry, Host profiles)
        src_ip = str(flow_meta.get("src_ip", flow_meta.get("saddr", "192.168.1.100")))
        dst_ip = str(flow_meta.get("dst_ip", flow_meta.get("daddr", "10.0.0.1")))
        src_port = int(flow_meta.get("src_port", flow_meta.get("sport", 49152)))
        dst_port = int(flow_meta.get("dst_port", flow_meta.get("dport", 443)))
        proto = str(flow_meta.get("protocol", flow_meta.get("proto", "tcp"))).upper()
        pkt_bytes = int(flow_meta.get("length", flow_meta.get("bytes", 500)))

        if persist:
            try:
                # Log flow event
                flow_rec = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=proto,
                    packet_size=pkt_bytes,
                    anomaly_score=anomaly_score,
                    is_anomaly=is_threat,
                    severity=risk_eval["severity"]
                )
                db.session.add(flow_rec)

                # If threshold exceeded, create Alert and update Host Profile
                if is_threat and explanation_data:
                    alert_uuid = f"ALT-{uuid.uuid4().hex[:10].upper()}"
                    new_alert = Alert(
                        alert_uuid=alert_uuid,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        anomaly_score=anomaly_score,
                        z_score=risk_eval["z_score"],
                        risk_score=risk_eval["risk_score"],
                        severity=risk_eval["severity"],
                        confidence=risk_eval["confidence"],
                        packet_count=int(flow_meta.get("pkts", 1)),
                        bytes_transferred=pkt_bytes,
                        off_hours=risk_eval["off_hours"],
                        is_external_dst=risk_eval["is_external_dst"],
                        top_features_json=json.dumps(explanation_data["top_features"]),
                        explanation_text=explanation_data["explanation_text"],
                        mitigation_text=json.dumps(explanation_data["mitigation_steps"]),
                        status="OPEN"
                    )
                    db.session.add(new_alert)
                    alert_obj = new_alert

                    # Update internal host risk profile
                    host = HostProfile.query.filter_by(ip_address=src_ip).first()
                    if not host:
                        host = HostProfile(
                            ip_address=src_ip,
                            hostname=f"ws-{src_ip.split('.')[-1]}",
                            department="Engineering" if "105" in src_ip else "Finance",
                            current_risk_score=risk_eval["risk_score"],
                            alert_count=1,
                            total_outbound_bytes=pkt_bytes,
                            is_flagged=risk_eval["severity"] in ["HIGH", "CRITICAL"],
                            last_anomaly_at=datetime.now(timezone.utc)
                        )
                        db.session.add(host)
                    else:
                        host.current_risk_score = max(host.current_risk_score, risk_eval["risk_score"])
                        host.alert_count += 1
                        host.total_outbound_bytes += pkt_bytes
                        if risk_eval["severity"] in ["HIGH", "CRITICAL"]:
                            host.is_flagged = True
                        host.last_anomaly_at = datetime.now(timezone.utc)

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"[Database Error during process_flow]: {e}")

        # 6. Prepare real-time event packet for UI and API response
        result_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "bytes": pkt_bytes,
            "anomaly_score": round(anomaly_score, 4),
            "z_score": round(risk_eval["z_score"], 2),
            "risk_score": round(risk_eval["risk_score"], 1),
            "severity": risk_eval["severity"],
            "is_threat": is_threat,
            "confidence": risk_eval["confidence"],
            "explanation": explanation_data["explanation_text"] if explanation_data else None,
            "top_features": explanation_data["top_features"] if explanation_data else [],
            "mitigation_steps": explanation_data["mitigation_steps"] if explanation_data else [],
            "radar_metrics": explanation_data["radar_metrics"] if explanation_data else [],
            "alert_uuid": alert_obj.alert_uuid if alert_obj else None
        }

        # 7. Broadcast to live SSE stream listeners
        self._broadcast(result_event)

        return result_event
