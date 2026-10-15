"""
SQLAlchemy Database Models for Insider Threat Detection Backend
"""
from datetime import datetime, timezone
import json
from core.database import db

class Alert(db.Model):
    """
    Persisted alert triggered when KitNET anomaly score and Risk Engine rules
    identify abnormal encrypted traffic characteristic of data exfiltration.
    """
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Network 5-tuple
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    dst_ip = db.Column(db.String(45), nullable=False, index=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True, index=True)
    protocol = db.Column(db.String(10), default="TCP")

    # Threat and Scoring Metrics
    anomaly_score = db.Column(db.Float, nullable=False)
    z_score = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)   # 0 to 100
    severity = db.Column(db.String(16), nullable=False, default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    confidence = db.Column(db.Float, default=0.85)

    # Encrypted Traffic Exfiltration Attributes
    flow_duration = db.Column(db.Float, default=0.0)
    packet_count = db.Column(db.Integer, default=1)
    bytes_transferred = db.Column(db.BigInteger, default=0)
    off_hours = db.Column(db.Boolean, default=False)
    is_external_dst = db.Column(db.Boolean, default=True)

    # Explainable AI (XAI) outputs
    top_features_json = db.Column(db.Text, nullable=True) # JSON list of feature attributions
    explanation_text = db.Column(db.Text, nullable=True)
    mitigation_text = db.Column(db.Text, nullable=True)

    # Workflow & Incident Response Status
    status = db.Column(db.String(24), default="OPEN", index=True) # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    analyst_notes = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        try:
            top_features = json.loads(self.top_features_json) if self.top_features_json else []
        except Exception:
            top_features = []
        return {
            "id": self.id,
            "alert_uuid": self.alert_uuid,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "anomaly_score": round(self.anomaly_score, 4),
            "z_score": round(self.z_score, 2),
            "risk_score": round(self.risk_score, 1),
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "flow_duration": round(self.flow_duration, 3),
            "packet_count": self.packet_count,
            "bytes_transferred": self.bytes_transferred,
            "off_hours": self.off_hours,
            "is_external_dst": self.is_external_dst,
            "top_features": top_features,
            "explanation": self.explanation_text,
            "mitigation": self.mitigation_text,
            "status": self.status,
            "analyst_notes": self.analyst_notes,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None
        }


class FlowRecord(db.Model):
    """
    High-volume processed flow log for real-time telemetry and dashboard charts.
    """
    __tablename__ = "flow_records"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), default="TCP")
    packet_size = db.Column(db.Integer, default=0)
    anomaly_score = db.Column(db.Float, default=0.0)
    is_anomaly = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String(16), default="NORMAL")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": self.is_anomaly,
            "severity": self.severity
        }


class HostProfile(db.Model):
    """
    Internal host/endpoint profile tracking cumulative insider risk,
    anomalous outbound data volume, and historical alerts.
    """
    __tablename__ = "host_profiles"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(128), nullable=True)
    department = db.Column(db.String(64), default="Engineering")
    assigned_user = db.Column(db.String(64), nullable=True)
    
    current_risk_score = db.Column(db.Float, default=10.0) # 0 to 100
    alert_count = db.Column(db.Integer, default=0)
    total_outbound_bytes = db.Column(db.BigInteger, default=0)
    is_flagged = db.Column(db.Boolean, default=False)
    last_anomaly_at = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "hostname": self.hostname or f"host-{self.ip_address.replace('.', '-')}",
            "department": self.department,
            "assigned_user": self.assigned_user or "unknown_user",
            "current_risk_score": round(self.current_risk_score, 1),
            "alert_count": self.alert_count,
            "total_outbound_bytes": self.total_outbound_bytes,
            "is_flagged": self.is_flagged,
            "last_anomaly_at": self.last_anomaly_at.isoformat() if self.last_anomaly_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }


class ModelBaseline(db.Model):
    """
    Stores metadata for trained KitNET baselines.
    """
    __tablename__ = "model_baselines"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    version = db.Column(db.String(32), default="v1.0")
    trained_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    training_samples = db.Column(db.Integer, default=0)
    feature_dimension = db.Column(db.Integer, default=100)
    num_clusters = db.Column(db.Integer, default=0)
    mean_baseline_error = db.Column(db.Float, default=0.0)
    std_baseline_error = db.Column(db.Float, default=0.0)
    max_baseline_error = db.Column(db.Float, default=0.0)
    dataset_name = db.Column(db.String(128), default="BoT-IoT Normal")
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "training_samples": self.training_samples,
            "feature_dimension": self.feature_dimension,
            "num_clusters": self.num_clusters,
            "mean_baseline_error": round(self.mean_baseline_error, 4),
            "std_baseline_error": round(self.std_baseline_error, 4),
            "max_baseline_error": round(self.max_baseline_error, 4),
            "dataset_name": self.dataset_name,
            "is_active": self.is_active
        }
