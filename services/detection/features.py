"""
Normalised detector inputs
===========================
`EventFeatures.from_event(row)` derives organisation-oriented quantities from a stored
event. Anything that cannot be derived is None — detectors report not_evaluated for it.

network_flow    outbound/inbound bytes come from the aggregator's org orientation
                (internal endpoint → external endpoint), never from initiator order.
network_record  directional bytes only from explicit fields in the original record
                (sbytes/dbytes, orig_bytes/resp_bytes, src_bytes/dst_bytes, bytes_out/bytes_in);
                a record's "bytes" total is not split by guesswork.
network_packet  not evaluated by rule detectors — every packet is inside its flow, so
                evaluating both would double-count one connection.
application_activity  user identity from the server-side session only.
"""
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from core.models import EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD
from core.timeutil import to_epoch
from services.network_metadata import org_orientation

COMPLETED_END_REASONS = {"tcp_close", "idle_timeout", "active_timeout", "collector_stopped", "pcap_end", "evicted"}
_DIRECTIONAL_PAIRS = (("sbytes", "dbytes"), ("orig_bytes", "resp_bytes"), ("src_bytes", "dst_bytes"),
                      ("bytes_out", "bytes_in"), ("out_bytes", "in_bytes"))


def _num(v) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f >= 0 else None   # NaN / negative → unusable


@dataclass
class EventFeatures:
    event_type: str
    event_uuid: str
    ts: Optional[float]
    end_ts: Optional[float] = None
    duration: Optional[float] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    org_direction: str = "unknown"
    internal_ip: Optional[str] = None
    external_ip: Optional[str] = None
    outbound_bytes: Optional[float] = None
    inbound_bytes: Optional[float] = None
    outbound_packets: Optional[float] = None
    inbound_packets: Optional[float] = None
    service_port: Optional[int] = None        # responder port
    responder_ip: Optional[str] = None
    initiator_internal: Optional[bool] = None
    completed: bool = False
    end_reason: Optional[str] = None
    tcp_outcome: Optional[str] = None
    app_protocol: Optional[str] = None
    sni: Optional[str] = None
    tls: Dict[str, Any] = field(default_factory=dict)
    dns: Optional[Dict[str, Any]] = None
    outbound_side: Optional[Dict[str, Any]] = None   # per-direction stats of the internal sender
    init_mac: Optional[str] = None
    # identity
    entity_key: Optional[str] = None
    entity_kind: Optional[str] = None          # device | addr | user
    device_key: Optional[str] = None
    user_id: Optional[int] = None
    # application
    action: Optional[str] = None
    outcome: Optional[str] = None
    app: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None

    @property
    def destination(self) -> Optional[str]:
        """Observed SNI when present, otherwise the external IP. Never an invented hostname."""
        return self.sni or self.external_ip

    @property
    def destination_kind(self) -> Optional[str]:
        return "domain" if self.sni else ("ip" if self.external_ip else None)

    @classmethod
    def from_event(cls, ev) -> "EventFeatures":
        d = ev.details
        f = cls(event_type=ev.event_type, event_uuid=ev.event_uuid, ts=to_epoch(ev.event_time),
                protocol=ev.protocol, src_ip=ev.src_ip, dst_ip=ev.dst_ip, src_port=ev.src_port,
                dst_port=ev.dst_port, user_id=ev.user_id, source=ev.source)
        if ev.event_type == EVENT_NETWORK_FLOW:
            f.end_ts = _num(d.get("end_time"))
            f.duration = _num(d.get("duration_s", ev.flow_duration))
            f.end_reason = d.get("end_reason")
            f.completed = f.end_reason in COMPLETED_END_REASONS
            f.org_direction = d.get("org_direction") or org_orientation(ev.src_ip, ev.dst_ip)["direction"]
            f.internal_ip, f.external_ip = d.get("internal_ip"), d.get("external_ip")
            f.outbound_bytes, f.inbound_bytes = _num(d.get("outbound_bytes")), _num(d.get("inbound_bytes"))
            f.outbound_packets, f.inbound_packets = _num(d.get("outbound_packets")), _num(d.get("inbound_packets"))
            f.service_port, f.responder_ip = ev.dst_port, ev.dst_ip
            f.tcp_outcome, f.app_protocol = d.get("tcp_outcome"), d.get("app_protocol")
            f.tls = d.get("tls") or {}
            f.sni = (f.tls.get("sni") or None)
            f.dns = d.get("dns")
            f.init_mac = d.get("init_mac")
            if f.org_direction == "outbound":
                f.outbound_side, f.initiator_internal = d.get("fwd"), True
            elif f.org_direction == "inbound":
                f.outbound_side, f.initiator_internal = d.get("bwd"), False
            elif f.org_direction == "internal":
                f.initiator_internal = True
        elif ev.event_type == EVENT_NETWORK_RECORD:
            orient = org_orientation(ev.src_ip, ev.dst_ip)
            f.org_direction = orient["direction"]
            f.duration = _num(ev.flow_duration)
            f.completed = True   # externally supplied records describe finished connections
            f.service_port, f.responder_ip = ev.dst_port, ev.dst_ip
            raw = {}
            try:
                raw = {str(k).lower(): v for k, v in json.loads(ev.raw_event_json or "{}").items()}
            except (ValueError, AttributeError):
                raw = {}
            fwd = bwd = None
            for a, b in _DIRECTIONAL_PAIRS:
                if a in raw and b in raw:
                    fwd, bwd = _num(raw[a]), _num(raw[b])
                    break
            if orient["internal_side"] == "a":
                f.internal_ip, f.external_ip, f.outbound_bytes, f.inbound_bytes = ev.src_ip, ev.dst_ip, fwd, bwd
                f.initiator_internal = True
            elif orient["internal_side"] == "b":
                f.internal_ip, f.external_ip, f.outbound_bytes, f.inbound_bytes = ev.dst_ip, ev.src_ip, bwd, fwd
                f.initiator_internal = False
            elif orient["internal_side"] == "both":
                f.internal_ip, f.initiator_internal = ev.src_ip, True
            sni = raw.get("server_name") or raw.get("sni")
            f.sni = str(sni).lower() if sni else None
        elif ev.event_type == EVENT_APPLICATION:
            f.action, f.outcome, f.app = ev.action, ev.outcome, d
            f.src_ip = ev.src_ip
        return f
