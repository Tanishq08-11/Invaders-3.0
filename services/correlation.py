"""
Application ↔ network correlation (conservative)
==================================================
Links an `application_activity` event (a portal upload/download by an authenticated
user) to `network_flow` events only when there is specific evidence. Each link records
its method, confidence, time offset and a plain-language rationale for the analyst.

Evidence available:
  • the portal sees the request's client address (no proxy handling is configured, so
    this is the direct peer address) and the authenticated user;
  • the collector sees flows with endpoints, ports, timing and byte counts.

An IP address does not identify a person (NAT, shared hosts, proxies). Therefore every
rule first requires that, around the activity, only ONE portal user was seen on that
client address; otherwise the activity is marked `shared_address` and left uncorrelated.

Rules
  app_server_connection (high)
      The flow is the client's own TCP connection to the portal (other endpoint port in
      APP_SERVER_PORTS), it was open when the request happened, and its volume in the
      relevant direction is at least the file size. Recorded only if exactly ONE flow
      qualifies; if several do (browsers keep parallel connections) the activity is
      marked `ambiguous` and any earlier link of this kind is withdrawn.
  address_time_proximity (low)        — downloads only
      A flow initiated from the same client address to an external (public) address,
      starting within CORRELATION_WINDOW_S after the download, carrying at least as many
      outbound bytes as the downloaded file. This is context for review only: encrypted
      traffic cannot show that the flow carried the file (and a compressed copy would
      be smaller and not match).

Packets and externally supplied records are never correlated; only completed flows.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from flask import current_app

from config import Config
from core.database import db
from core.models import (
    CORRELATION_ADDRESS_PROXIMITY,
    CORRELATION_APP_SERVER_CONNECTION,
    EVENT_APPLICATION,
    EVENT_NETWORK_FLOW,
    Event,
    EventCorrelation,
)
from services.network_metadata import is_external

TIME_SLACK_S = 2.0  # clock granularity between the portal and capture timestamps


def _cfg(name):
    try:
        return current_app.config.get(name, getattr(Config, name))
    except RuntimeError:
        return getattr(Config, name)


def _ts(dt: Optional[datetime]) -> Optional[float]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _naive(ts: float) -> datetime:
    # Stored datetimes are naive UTC on SQLite; compare like with like.
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def _flow_window(flow: Event):
    d = flow.details
    start = d.get("start_time", _ts(flow.event_time))
    end = d.get("end_time", start + (flow.flow_duration or 0.0) if start is not None else None)
    return start, end


def _client_bytes(flow: Event, client_ip: str):
    """(bytes sent by client, bytes received by client) within this flow."""
    d = flow.details
    fwd, bwd = d.get("fwd_bytes"), d.get("bwd_bytes")
    if fwd is None or bwd is None:
        return None, None
    return (fwd, bwd) if flow.src_ip == client_ip else (bwd, fwd)


def _users_on_address(client_ip: str, t: float) -> set:
    lookback = float(_cfg("CORRELATION_ADDRESS_LOOKBACK_S"))
    window = float(_cfg("CORRELATION_WINDOW_S"))
    rows = (
        db.session.query(Event.user_id)
        .filter(
            Event.event_type == EVENT_APPLICATION,
            Event.src_ip == client_ip,
            Event.user_id.isnot(None),
            Event.event_time >= _naive(t - lookback),
            Event.event_time <= _naive(t + window),
        )
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def _link(app_event: Event, flow: Event, method: str, confidence: str, delta: float, rationale: str):
    existing = EventCorrelation.query.filter_by(
        application_event_id=app_event.id, network_event_id=flow.id
    ).first()
    if existing:
        return None
    row = EventCorrelation(
        correlation_uuid=f"COR-{uuid.uuid4().hex[:12].upper()}",
        application_event_id=app_event.id,
        network_event_id=flow.id,
        user_id=app_event.user_id,
        client_ip=app_event.src_ip,
        method=method,
        confidence=confidence,
        time_delta_s=delta,
        rationale=rationale,
    )
    db.session.add(row)
    return row


def evaluate_application_event(app_event: Event) -> List[EventCorrelation]:
    """(Re)evaluate every rule for one application event. Caller commits."""
    client_ip = app_event.src_ip
    t = _ts(app_event.event_time)
    details = app_event.details
    summary: Dict = {"evaluated_at": datetime.now(timezone.utc).isoformat()}
    new_links: List[EventCorrelation] = []

    if not client_ip or t is None:
        summary["status"] = "no_client_address"
    else:
        users = _users_on_address(client_ip, t)
        if len(users) > 1:
            summary["status"] = "shared_address"
            summary["users_on_address"] = len(users)
        else:
            new_links += _rule_app_server(app_event, client_ip, t, details, summary)
            if app_event.action == "download" and app_event.outcome == "success" and _cfg("CORRELATION_ADDRESS_PROXIMITY"):
                new_links += _rule_proximity(app_event, client_ip, t, details)
            # Autoflush makes rows added/deleted above visible to this count.
            linked = EventCorrelation.query.filter_by(application_event_id=app_event.id).count()
            summary["links"] = linked
            summary.setdefault("status", "correlated" if linked else "none")

    app_event.details_json = json.dumps({**details, "correlation": summary}, default=str)
    return new_links


def _rule_app_server(app_event, client_ip, t, details, summary) -> List[EventCorrelation]:
    ports = set(_cfg("APP_SERVER_PORTS") or [])
    if not ports:
        return []
    size = details.get("size_bytes") or 0
    max_age = float(_cfg("FLOW_ACTIVE_TIMEOUT_S")) + TIME_SLACK_S
    flows = Event.query.filter(
        Event.event_type == EVENT_NETWORK_FLOW,
        Event.protocol == "TCP",
        db.or_(Event.src_ip == client_ip, Event.dst_ip == client_ip),
        Event.event_time >= _naive(t - max_age),
        Event.event_time <= _naive(t + TIME_SLACK_S),
    ).all()

    qualifying = []
    for f in flows:
        server_port = f.dst_port if f.src_ip == client_ip else f.src_port
        if server_port not in ports:
            continue
        start, end = _flow_window(f)
        if start is None or not (start - TIME_SLACK_S <= t <= (end or start) + TIME_SLACK_S):
            continue
        sent, received = _client_bytes(f, client_ip)
        relevant = sent if app_event.action == "upload" else received
        if size and (relevant is None or relevant < size):
            continue
        qualifying.append((f, start))

    summary["app_server_candidates"] = len(qualifying)
    existing = EventCorrelation.query.filter_by(
        application_event_id=app_event.id, method=CORRELATION_APP_SERVER_CONNECTION
    ).all()
    if len(qualifying) != 1:
        if len(qualifying) > 1:
            summary["status"] = "ambiguous"
            for row in existing:  # a later qualifying flow made an earlier match uncertain
                db.session.delete(row)
        return []
    flow, start = qualifying[0]
    if any(r.network_event_id != flow.id for r in existing):
        for r in existing:
            db.session.delete(r)
    direction = "client→portal" if app_event.action == "upload" else "portal→client"
    link = _link(
        app_event, flow, CORRELATION_APP_SERVER_CONNECTION, "high", start - t,
        f"Only flow between {client_ip} and the portal port that was open at the time of this "
        f"{app_event.action} with at least {size} bytes {direction}.",
    )
    return [link] if link else []


def _rule_proximity(app_event, client_ip, t, details) -> List[EventCorrelation]:
    window = float(_cfg("CORRELATION_WINDOW_S"))
    size = details.get("size_bytes") or 0
    ports = set(_cfg("APP_SERVER_PORTS") or [])
    cap = int(_cfg("CORRELATION_MAX_LINKS_PER_EVENT"))
    already = EventCorrelation.query.filter_by(
        application_event_id=app_event.id, method=CORRELATION_ADDRESS_PROXIMITY
    ).count()
    if already >= cap:
        return []
    flows = (
        Event.query.filter(
            Event.event_type == EVENT_NETWORK_FLOW,
            Event.src_ip == client_ip,
            Event.event_time >= _naive(t),
            Event.event_time <= _naive(t + window),
        )
        .order_by(Event.event_time.asc())
        .limit(500)
        .all()
    )
    links = []
    for f in flows:
        if len(links) + already >= cap:
            break
        if not is_external(f.dst_ip) or f.dst_port in ports:
            continue
        sent = f.details.get("fwd_bytes")
        if sent is None or (size and sent < size):
            continue
        start, _ = _flow_window(f)
        link = _link(
            app_event, f, CORRELATION_ADDRESS_PROXIMITY, "low", (start or t) - t,
            f"Flow from the same client address ({client_ip}, one portal user seen on it) to external "
            f"{f.dst_ip}:{f.dst_port} began {round((start or t) - t, 1)}s after the download and sent "
            f"{sent} bytes (file: {size} bytes). Encrypted traffic does not show whether the file was carried.",
        )
        if link:
            links.append(link)
    return links


def evaluate_network_flow(flow: Event) -> List[Event]:
    """Re-evaluate application events that this completed flow could relate to. Caller commits."""
    if flow.event_type != EVENT_NETWORK_FLOW:
        return []
    start, end = _flow_window(flow)
    if start is None:
        return []
    window = float(_cfg("CORRELATION_WINDOW_S"))
    candidates = Event.query.filter(
        Event.event_type == EVENT_APPLICATION,
        Event.src_ip.in_([ip for ip in (flow.src_ip, flow.dst_ip) if ip]),
        Event.event_time >= _naive(start - window - TIME_SLACK_S),
        Event.event_time <= _naive((end or start) + TIME_SLACK_S),
    ).all()
    for app_event in candidates:
        evaluate_application_event(app_event)
    return candidates
