"""
Database Models — Person 4 Backend Spec
========================================
Tables: events, alerts, devices, model_versions, analyst_actions, event_correlations

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
import re
from core.database import db


def iso_utc(dt):
    """ISO-8601 string with an explicit UTC offset (SQLite hands back naive datetimes)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# Risk-engine factor sentences -> stable signal codes consumed by the dashboard.
_SIGNAL_PATTERNS = [
    (re.compile(r"external destination", re.I), "destination_external"),
    (re.compile(r"suspicious destination port", re.I), "suspicious_port"),
    (re.compile(r"encrypted channel", re.I), "encrypted_channel"),
    (re.compile(r"off-hours", re.I), "off_hours_activity"),
    (re.compile(r"near-mtu", re.I), "outbound_volume_mtu_framing"),
    (re.compile(r"bulk data transfer", re.I), "outbound_volume_bulk_transfer"),
]


def source_to_data_source(source):
    """Event source → dashboard data_source (live | simulation | replay | pcap | unknown)."""
    return {
        "live_capture": "live",
        "simulation": "simulation",
        "dataset_replay": "replay",
        "pcap": "pcap",
    }.get(source or "", "unknown")


def risk_factors_to_signals(factors):
    signals = []
    for label in factors or []:
        if not isinstance(label, str):
            continue
        code = next((c for p, c in _SIGNAL_PATTERNS if p.search(label)), "anomaly")
        signals.append({"code": code, "label": label})
    return signals


# ---------------------------------------------------------------------------
# Event envelope vocabulary (see README "Event pipeline")
# ---------------------------------------------------------------------------
EVENT_NETWORK_PACKET = "network_packet"        # one observed packet (live capture / PCAP / simulation)
EVENT_NETWORK_FLOW = "network_flow"            # completed bidirectional flow built by the aggregator
EVENT_NETWORK_RECORD = "network_record"        # externally supplied flow record (POST /events, dataset replay)
EVENT_APPLICATION = "application_activity"     # portal file operation recorded by the application itself
NETWORK_EVENT_TYPES = (EVENT_NETWORK_PACKET, EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
# Each packet is also counted inside its flow, so traffic totals use flows + records only.
TRAFFIC_EVENT_TYPES = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
EVENT_TYPES = NETWORK_EVENT_TYPES + (EVENT_APPLICATION,)

SOURCE_LIVE = "live_capture"
SOURCE_PCAP = "pcap"
SOURCE_SIMULATION = "simulation"
SOURCE_REPLAY = "dataset_replay"
SOURCE_API = "api"
SOURCE_APPLICATION = "application"
SOURCE_LEGACY = "legacy"                       # rows stored before the envelope existed

# Detection status — never implies a verdict unless it is "scored".
DETECTION_PENDING = "pending"
DETECTION_SCORED = "scored"
DETECTION_UNAVAILABLE = "unavailable"          # no detector loaded / detector disabled
DETECTION_UNSUPPORTED = "unsupported"          # active detector does not accept this event type
DETECTION_FAILED = "failed"
DETECTION_NOT_APPLICABLE = "not_applicable"    # application evidence is never model input

PROCESSING_STORED = "stored"
PROCESSING_COMPLETE = "complete"
PROCESSING_DOWNSTREAM_ERROR = "downstream_error"


def _loads(raw, default=None):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# 1. Events — every ingested network observation or application activity record
# ---------------------------------------------------------------------------
class Event(db.Model):
    __tablename__ = "events"
    __table_args__ = (
        db.Index("ix_events_type_received", "event_type", "received_at"),
        # Unique index (not an inline constraint) so migrated databases get the identical object.
        db.Index("uq_events_dedup_key", "dedup_key", unique=True),
    )

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_uuid  = db.Column(db.String(64), unique=True, nullable=False, index=True)
    received_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Original event timestamp (from the source / dataset)
    event_time  = db.Column(db.DateTime, nullable=True)

    # Envelope
    event_type  = db.Column(db.String(32), nullable=False, default=EVENT_NETWORK_RECORD)
    source      = db.Column(db.String(32), nullable=False, default=SOURCE_API, index=True)
    # Idempotency key (e.g. "file_activity:42", "flow:<id>"); NULL when the source has none.
    dedup_key   = db.Column(db.String(160), nullable=True)
    processing_status = db.Column(db.String(24), nullable=False, default=PROCESSING_STORED)
    processing_error  = db.Column(db.Text, nullable=True)   # downstream (non-detector) failures
    detection_status  = db.Column(db.String(24), nullable=False, default=DETECTION_PENDING, index=True)

    # Identity — only set when reliably known (authenticated session / verified mapping)
    user_id     = db.Column(db.Integer, nullable=True, index=True)  # users live in the auth database
    device_id   = db.Column(db.String(64), nullable=True)

    # Application activity
    action      = db.Column(db.String(32), nullable=True)   # upload | download | denied …
    outcome     = db.Column(db.String(16), nullable=True)   # success | denied | failed

    # Network linkage
    flow_id     = db.Column(db.String(40), nullable=True, index=True)
    direction   = db.Column(db.String(16), nullable=True)   # outbound | inbound | internal | external
    # Type-specific metadata (flow statistics, TLS handshake metadata, application context)
    details_json = db.Column(db.Text, nullable=True)

    # Network 5-tuple (encrypted header metadata — payload is NEVER stored).
    # For application events src_ip is the client address seen by the portal server.
    src_ip      = db.Column(db.String(45), nullable=True, index=True)
    dst_ip      = db.Column(db.String(45), nullable=True, index=True)
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

    @property
    def details(self):
        return _loads(self.details_json, {}) or {}

    def to_dict(self, include_features=False):
        details = self.details
        tls = details.get("tls") or {}
        is_network = self.event_type in NETWORK_EVENT_TYPES
        is_flow = self.event_type == EVENT_NETWORK_FLOW
        d = {
            "id":               self.id,
            "event_uuid":       self.event_uuid,
            "event_type":       self.event_type,
            "source":           self.source,
            "data_source":      source_to_data_source(self.source),
            "processing_status": self.processing_status,
            "processing_error": self.processing_error,
            "detection_status": self.detection_status,
            "user_id":          self.user_id,
            "action":           self.action,
            "outcome":          self.outcome,
            "flow_id":          self.flow_id,
            "direction":        self.direction,
            "details":          details,
            "tls_sni":          tls.get("sni"),
            "received_at":      self.received_at.isoformat() if self.received_at else None,
            "event_time":       self.event_time.isoformat() if self.event_time else None,
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "src_port":         self.src_port,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "bytes_transferred":self.bytes_transferred,
            "packet_count":     self.packet_count,
            "flow_duration":    round(self.flow_duration, 4) if self.flow_duration is not None else None,
            "ai_processed":     self.ai_processed,
            "ai_error":         self.ai_error,
            "anomaly_score":    round(self.anomaly_score, 6) if self.anomaly_score is not None else None,
            "alert_id":         self.alert_id,
            # Dashboard (NetworkEvent) contract
            "timestamp":        iso_utc(self.event_time or self.received_at),
            # Network events: the device identifier is the source address (no identity implied).
            # Application events: only a reliably known device, otherwise null.
            "device_id":        self.device_id or (self.src_ip if is_network else None),
            "bytes_out":        details.get("fwd_bytes", self.bytes_transferred) if is_flow else self.bytes_transferred,
            "bytes_in":         details.get("bwd_bytes") if is_flow else None,
            "packets_out":      details.get("fwd_packets", self.packet_count) if is_flow else self.packet_count,
            "packets_in":       details.get("bwd_packets") if is_flow else None,
            "duration_seconds": round(self.flow_duration, 4) if self.flow_duration is not None else None,
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

    # Where the triggering event came from (live_capture, pcap, simulation, dataset_replay, api …)
    source          = db.Column(db.String(32), nullable=True)

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

    def _dashboard_fields(self):
        """Fields in the shape the SOC dashboard expects (see frontend/src/api/schemas.ts)."""
        return {
            "device_id":        self.src_ip,
            "source_ip":        self.src_ip,
            "destination":      self.dst_ip,
            "destination_port": self.dst_port,
            "bytes_out":        self.bytes_transferred,
            "scoring_status":   "ok",
            "signals":          risk_factors_to_signals(self._parse_json(self.risk_factors_json)),
            "source":           self.source,
            "data_source":      source_to_data_source(self.source),
        }

    def to_dict(self):
        evidence = self._parse_json(self.evidence_json)
        return {
            **self._dashboard_fields(),
            "risk_contributions": [
                {
                    "signal":       f.get("feature_name", "feature"),
                    "label":        f.get("display_name"),
                    "contribution": f.get("contribution_pct", 0.0),
                    "explanation":  f.get("description"),
                }
                for f in evidence if isinstance(f, dict)
            ],
            "analyst_note":    self.analyst_notes,
            "model_version":   self.model_version.version if self.model_version else None,
            "metadata": {
                "alert_uuid":      self.alert_uuid,
                "protocol":        self.protocol,
                "source_port":     self.src_port,
                "anomaly_score":   round(self.anomaly_score, 4),
                "z_score":         round(self.z_score, 2),
                "confidence":      round(self.confidence, 2),
                "off_hours":       bool(self.off_hours),
                "external_destination": bool(self.is_external_dst),
                "disposition":     self.disposition,
            },
            "id":              self.id,
            "alert_uuid":      self.alert_uuid,
            "created_at":      iso_utc(self.created_at),
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
            "evidence":        evidence,
            "explanation":     self.explanation,
            "mitigation":      self._parse_json(self.mitigation_json),
            "risk_factors":    self._parse_json(self.risk_factors_json),
            "status":          self.status,
            "disposition":     self.disposition,
            "analyst_notes":   self.analyst_notes,
            "updated_at":      iso_utc(self.updated_at),
            "resolved_at":     iso_utc(self.resolved_at),
            "model_version_id": self.model_version_id,
        }

    def to_summary(self):
        """Lightweight dict used in list views."""
        return {
            **self._dashboard_fields(),
            "id":          self.id,
            "alert_uuid":  self.alert_uuid,
            "created_at":  iso_utc(self.created_at),
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
# 3b. Event correlations — reviewable evidence links between application and network events
# ---------------------------------------------------------------------------
CORRELATION_APP_SERVER_CONNECTION = "app_server_connection"   # the flow IS the client's portal connection
CORRELATION_ADDRESS_PROXIMITY = "address_time_proximity"      # same client address, external dst, close in time


class EventCorrelation(db.Model):
    __tablename__ = "event_correlations"
    __table_args__ = (
        db.UniqueConstraint("application_event_id", "network_event_id", name="uq_correlation_pair"),
    )

    id                   = db.Column(db.Integer, primary_key=True, autoincrement=True)
    correlation_uuid     = db.Column(db.String(64), unique=True, nullable=False)
    application_event_id = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=False, index=True)
    network_event_id     = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=False, index=True)
    user_id              = db.Column(db.Integer, nullable=True)
    client_ip            = db.Column(db.String(45), nullable=True)
    method               = db.Column(db.String(32), nullable=False)
    confidence           = db.Column(db.String(16), nullable=False)   # high | low
    time_delta_s         = db.Column(db.Float, nullable=True)         # network start − application time
    rationale            = db.Column(db.Text, nullable=True)
    created_at           = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    application_event = db.relationship("Event", foreign_keys=[application_event_id])
    network_event     = db.relationship("Event", foreign_keys=[network_event_id])

    def to_dict(self):
        return {
            "correlation_id":       self.correlation_uuid,
            "application_event_id": self.application_event.event_uuid if self.application_event else None,
            "network_event_id":     self.network_event.event_uuid if self.network_event else None,
            "network_flow_id":      self.network_event.flow_id if self.network_event else None,
            "user_id":              self.user_id,
            "client_ip":            self.client_ip,
            "method":               self.method,
            "confidence":           self.confidence,
            "time_delta_s":         round(self.time_delta_s, 3) if self.time_delta_s is not None else None,
            "rationale":            self.rationale,
            "created_at":           iso_utc(self.created_at),
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


# ---------------------------------------------------------------------------
# 6. Users — portal accounts (employees and SOC analysts)
# ---------------------------------------------------------------------------
ROLE_EMPLOYEE = "EMPLOYEE"
ROLE_ANALYST = "SECURITY_ANALYST"
# Analyst capabilities plus service operations: collector start/stop, PCAP analysis,
# dataset replay, model management.
ROLE_ADMIN = "ADMIN"
SOC_ROLES = (ROLE_ANALYST, ROLE_ADMIN)


class User(db.Model):
    __tablename__ = "users"
    __bind_key__ = "auth"  # separate users database (config SQLALCHEMY_BINDS)

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username      = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name  = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(32), nullable=False, default=ROLE_EMPLOYEE)
    department    = db.Column(db.String(64), nullable=True, index=True)
    email         = db.Column(db.String(128), nullable=True)
    storage_quota_bytes = db.Column(db.BigInteger, default=1024 * 1024 * 1024)
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime, nullable=True)

    def storage_used_bytes(self):
        total = (
            db.session.query(db.func.coalesce(db.func.sum(StoredFile.size_bytes), 0))
            .filter(StoredFile.owner_id == self.id, StoredFile.kind == "file")
            .scalar()
        )
        return int(total or 0)

    def to_dict(self):
        d = {
            "id":           self.id,
            "username":     self.username,
            "display_name": self.display_name,
            "role":         self.role,
            "department":   self.department,
            "email":        self.email,
        }
        if self.role == ROLE_EMPLOYEE:
            d["storage_used_bytes"] = self.storage_used_bytes()
            d["storage_quota_bytes"] = self.storage_quota_bytes
        return d


# ---------------------------------------------------------------------------
# 7. Stored files — employee file portal (never an input to the anomaly model)
# ---------------------------------------------------------------------------
class StoredFile(db.Model):
    __tablename__ = "stored_files"
    __bind_key__ = "auth"  # separate users database (config SQLALCHEMY_BINDS)

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name        = db.Column(db.String(255), nullable=False)
    kind        = db.Column(db.String(8), nullable=False, default="file")  # file | folder
    parent_id   = db.Column(db.Integer, db.ForeignKey("stored_files.id"), nullable=True, index=True)
    owner_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    # Set on department shared folders and everything inside them; NULL = personal item.
    department  = db.Column(db.String(64), nullable=True, index=True)
    size_bytes  = db.Column(db.BigInteger, nullable=True)
    mime_type   = db.Column(db.String(128), nullable=True)
    storage_key = db.Column(db.String(64), nullable=True)  # on-disk name under UPLOAD_DIR
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    owner  = db.relationship("User")
    parent = db.relationship("StoredFile", remote_side=[id])

    def to_dict(self, permissions):
        return {
            "id":          self.id,
            "name":        self.name,
            "kind":        self.kind,
            "parent_id":   self.parent_id,
            "size_bytes":  self.size_bytes,
            "mime_type":   self.mime_type,
            "uploaded_at": iso_utc(self.uploaded_at),
            "owner":       self.owner.display_name if self.owner else (f"{self.department} (shared)" if self.department else None),
            "permissions": permissions,
        }


class FileActivity(db.Model):
    __tablename__ = "file_activity"
    __bind_key__ = "auth"  # separate users database (config SQLALCHEMY_BINDS)

    id        = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id   = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    action    = db.Column(db.String(16), nullable=False)  # upload | download | access | denied
    file_name = db.Column(db.String(255), nullable=True)
    result    = db.Column(db.String(16), nullable=False)  # success | denied | failed
    detail    = db.Column(db.String(255), nullable=True)
    # Outbox state for the matching application_activity event in the SOC database:
    # pending → recorded | failed (failed/pending rows are retried later).
    security_event_status = db.Column(db.String(16), nullable=True, index=True)
    security_event_uuid   = db.Column(db.String(64), nullable=True)
    # Outbox payload (client address, file id/size — never contents); cleared once recorded.
    security_event_payload = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id":        self.id,
            "timestamp": iso_utc(self.timestamp),
            "action":    self.action,
            "file_name": self.file_name,
            "result":    self.result,
            "detail":    self.detail,
        }
