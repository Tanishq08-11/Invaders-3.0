"""
Database Models — Person 4 Backend Spec
========================================
Tables: events, alerts, devices, model_versions, analyst_actions

Design goals:
  • Every ingested network event is persisted *before* the AI touches it.
  • If the detector fails, the event row records the failure (ai_error) and
    the alert is never created — no silent zero-score.
  • Alerts FK back to the originating event and the model version that
    produced them, so any result is fully traceable.
  • Analyst disposition changes are audit-logged in analyst_actions.
"""
from datetime import datetime, timezone
import json
from core.database import db


# ---------------------------------------------------------------------------
# 1. Events — every raw ingested network event
# ---------------------------------------------------------------------------
class Event(db.Model):
    __tablename__ = "events"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_uuid  = db.Column(db.String(64), unique=True, nullable=False, index=True)
    received_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Original event timestamp (from the source / dataset)
    event_time  = db.Column(db.DateTime, nullable=True)

    # Network 5-tuple (encrypted header metadata — payload is NEVER stored)
    src_ip      = db.Column(db.String(45), nullable=False, index=True)
    dst_ip      = db.Column(db.String(45), nullable=False, index=True)
    src_port    = db.Column(db.Integer, nullable=True)
    dst_port    = db.Column(db.Integer, nullable=True)
    protocol    = db.Column(db.String(10), default="TCP")

    # Volume / timing
    bytes_transferred = db.Column(db.BigInteger, default=0)
    packet_count      = db.Column(db.Integer, default=1)
    flow_duration     = db.Column(db.Float, default=0.0)

    # Raw payload preserved verbatim so the event can be re-processed later
    raw_event_json    = db.Column(db.Text, nullable=True)

    # AI processing outcome
    ai_processed      = db.Column(db.Boolean, default=False)
    ai_error          = db.Column(db.Text, nullable=True)
    anomaly_score     = db.Column(db.Float, nullable=True)   # NULL until AI runs
    feature_vector_json = db.Column(db.Text, nullable=True)  # extracted features

    # FK to the alert this event triggered (NULL if benign)
    alert_id          = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=True)

    # Relationship
    alert = db.relationship("Alert", backref=db.backref("source_events", lazy="dynamic"))

    def to_dict(self, include_features=False):
        d = {
            "id":               self.id,
            "event_uuid":       self.event_uuid,
            "received_at":      self.received_at.isoformat() if self.received_at else None,
            "event_time":       self.event_time.isoformat() if self.event_time else None,
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "src_port":         self.src_port,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "bytes_transferred":self.bytes_transferred,
            "packet_count":     self.packet_count,
            "flow_duration":    round(self.flow_duration, 4),
            "ai_processed":     self.ai_processed,
            "ai_error":         self.ai_error,
            "anomaly_score":    round(self.anomaly_score, 6) if self.anomaly_score is not None else None,
            "alert_id":         self.alert_id,
        }
        if include_features and self.feature_vector_json:
            try:
                d["feature_vector"] = json.loads(self.feature_vector_json)
            except Exception:
                d["feature_vector"] = None
        return d


# ---------------------------------------------------------------------------
# 2. Alerts — generated only when the AI flags an event as a threat
# ---------------------------------------------------------------------------
class Alert(db.Model):
    __tablename__ = "alerts"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_uuid  = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Severity & scoring — copied at alert-creation time so the alert is a snapshot
    severity    = db.Column(db.String(16), nullable=False, default="MEDIUM", index=True)
    risk_score  = db.Column(db.Float, nullable=False, default=0.0)
    anomaly_score = db.Column(db.Float, nullable=False, default=0.0)
    z_score     = db.Column(db.Float, nullable=False, default=0.0)
    confidence  = db.Column(db.Float, default=0.85)

    # Network context (denormalized for fast list queries)
    src_ip      = db.Column(db.String(45), nullable=False, index=True)
    dst_ip      = db.Column(db.String(45), nullable=False)
    src_port    = db.Column(db.Integer, nullable=True)
    dst_port    = db.Column(db.Integer, nullable=True)
    protocol    = db.Column(db.String(10), default="TCP")
    bytes_transferred = db.Column(db.BigInteger, default=0)

    # Contextual flags
    off_hours       = db.Column(db.Boolean, default=False)
    is_external_dst = db.Column(db.Boolean, default=True)

    # Evidence payload (XAI feature attribution + risk factors)
    evidence_json   = db.Column(db.Text, nullable=True)   # top_features list
    explanation     = db.Column(db.Text, nullable=True)    # human-readable narrative
    mitigation_json = db.Column(db.Text, nullable=True)    # playbook steps
    risk_factors_json = db.Column(db.Text, nullable=True)  # contextual risk factors

    # Investigation lifecycle
    status      = db.Column(db.String(24), default="open", index=True)
    disposition = db.Column(db.String(32), nullable=True)  # true_positive, false_positive, benign, etc.
    analyst_notes = db.Column(db.Text, nullable=True)
    updated_at  = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # Traceability
    model_version_id = db.Column(db.Integer, db.ForeignKey("model_versions.id"), nullable=True)
    model_version    = db.relationship("ModelVersion", backref="alerts")

    def _parse_json(self, raw):
        if not raw:
            return []
        try:
            return json.loads(raw)
        except Exception:
            return []

    def to_dict(self):
        return {
            "id":              self.id,
            "alert_uuid":      self.alert_uuid,
            "created_at":      self.created_at.isoformat() if self.created_at else None,
            "severity":        self.severity,
            "risk_score":      round(self.risk_score, 1),
            "anomaly_score":   round(self.anomaly_score, 4),
            "z_score":         round(self.z_score, 2),
            "confidence":      round(self.confidence, 2),
            "src_ip":          self.src_ip,
            "dst_ip":          self.dst_ip,
            "src_port":        self.src_port,
            "dst_port":        self.dst_port,
            "protocol":        self.protocol,
            "bytes_transferred": self.bytes_transferred,
            "off_hours":       self.off_hours,
            "is_external_dst": self.is_external_dst,
            "evidence":        self._parse_json(self.evidence_json),
            "explanation":     self.explanation,
            "mitigation":      self._parse_json(self.mitigation_json),
            "risk_factors":    self._parse_json(self.risk_factors_json),
            "status":          self.status,
            "disposition":     self.disposition,
            "analyst_notes":   self.analyst_notes,
            "updated_at":      self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at":     self.resolved_at.isoformat() if self.resolved_at else None,
            "model_version_id": self.model_version_id,
        }

    def to_summary(self):
        """Lightweight dict used in list views."""
        return {
            "id":          self.id,
            "alert_uuid":  self.alert_uuid,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
            "severity":    self.severity,
            "risk_score":  round(self.risk_score, 1),
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "dst_port":    self.dst_port,
            "status":      self.status,
            "disposition": self.disposition,
        }


# ---------------------------------------------------------------------------
# 3. Devices — internal host / endpoint profiles
# ---------------------------------------------------------------------------
class Device(db.Model):
    __tablename__ = "devices"

    id              = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id       = db.Column(db.String(64), unique=True, nullable=False, index=True)  # typically the IP
    hostname        = db.Column(db.String(128), nullable=True)
    department      = db.Column(db.String(64), nullable=True)
    assigned_user   = db.Column(db.String(64), nullable=True)

    risk_score      = db.Column(db.Float, default=0.0)
    alert_count     = db.Column(db.Integer, default=0)
    event_count     = db.Column(db.Integer, default=0)
    total_bytes_out = db.Column(db.BigInteger, default=0)
    is_flagged      = db.Column(db.Boolean, default=False)

    first_seen      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_alert_at   = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id":             self.id,
            "device_id":      self.device_id,
            "hostname":       self.hostname or f"host-{self.device_id.replace('.', '-')}",
            "department":     self.department,
            "assigned_user":  self.assigned_user,
            "risk_score":     round(self.risk_score, 1),
            "alert_count":    self.alert_count,
            "event_count":    self.event_count,
            "total_bytes_out":self.total_bytes_out,
            "is_flagged":     self.is_flagged,
            "first_seen":     self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":      self.last_seen.isoformat() if self.last_seen else None,
            "last_alert_at":  self.last_alert_at.isoformat() if self.last_alert_at else None,
        }


# ---------------------------------------------------------------------------
# 4. Model Versions — track which model version produced which results
# ---------------------------------------------------------------------------
class ModelVersion(db.Model):
    __tablename__ = "model_versions"

    id               = db.Column(db.Integer, primary_key=True, autoincrement=True)
    version          = db.Column(db.String(32), nullable=False, default="v1.0")
    trained_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    training_samples = db.Column(db.Integer, default=0)
    feature_dimension= db.Column(db.Integer, default=100)
    num_clusters     = db.Column(db.Integer, default=0)
    baseline_mean    = db.Column(db.Float, default=0.0)
    baseline_std     = db.Column(db.Float, default=0.0)
    baseline_max     = db.Column(db.Float, default=0.0)
    dataset_name     = db.Column(db.String(128), nullable=True)
    checkpoint_path  = db.Column(db.String(256), nullable=True)
    is_active        = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id":              self.id,
            "version":         self.version,
            "trained_at":      self.trained_at.isoformat() if self.trained_at else None,
            "training_samples":self.training_samples,
            "feature_dimension": self.feature_dimension,
            "num_clusters":    self.num_clusters,
            "baseline_mean":   round(self.baseline_mean, 6),
            "baseline_std":    round(self.baseline_std, 6),
            "baseline_max":    round(self.baseline_max, 6),
            "dataset_name":    self.dataset_name,
            "is_active":       self.is_active,
        }


# ---------------------------------------------------------------------------
# 5. Analyst Actions — audit trail for disposition / status changes
# ---------------------------------------------------------------------------
class AnalystAction(db.Model):
    __tablename__ = "analyst_actions"

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id    = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, index=True)
    action_type = db.Column(db.String(32), nullable=False)   # status_change, disposition_set, note_added
    field_name  = db.Column(db.String(32), nullable=True)
    old_value   = db.Column(db.String(128), nullable=True)
    new_value   = db.Column(db.String(128), nullable=True)
    analyst     = db.Column(db.String(64), nullable=True)
    performed_at= db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    alert       = db.relationship("Alert", backref=db.backref("analyst_actions", lazy="dynamic"))

    def to_dict(self):
        return {
            "id":          self.id,
            "alert_id":    self.alert_id,
            "action_type": self.action_type,
            "field_name":  self.field_name,
            "old_value":   self.old_value,
            "new_value":   self.new_value,
            "analyst":     self.analyst,
            "performed_at":self.performed_at.isoformat() if self.performed_at else None,
        }
