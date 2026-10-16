"""
D24 multi-stage exfiltration, D11 device silent / VPN gap, D25 telemetry health.

D24 only links observations through reliable relationships:
  • the same entity (registered device, internal address, or session user);
  • a registered device ↔ its registered owner (device registry);
  • application ↔ network events joined by a recorded EventCorrelation.
Events that are merely close in time are never linked.

D11 / D25 run in the periodic telemetry sweep (DetectionEngine.sweep), not per event.
D25 signals are telemetry-health (category "telemetry_health") and never create
security alerts.
"""
from datetime import datetime, timedelta, timezone

from core.database import db
from core.models import (
    EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, DetectionSignal, Event, EventCorrelation,
    RegisteredDevice,
)
from core.timeutil import naive_utc, to_epoch
from services.detection.base import G_CHAIN, G_HEALTH, NOT_EVALUATED, TRIGGERED, Detector

STAGES = {
    "collection": {"D16"},
    "exfiltration": {"D1", "D5", "D6", "D7", "D9", "D18", "D20", "D23"},
    "concealment": {"D12", "D17", "D21", "D26", "D8"},
    "anomalous_behaviour": {"D2", "D3", "D4", "D10", "D19", "D22", "D28"},
    "account_misuse": {"D13", "D14", "D15", "D27"},
}
STAGE_OF = {d: s for s, ds in STAGES.items() for d in ds}


class MultiStage(Detector):
    id, name, version, group = "D24", "Multi-stage exfiltration", "1.0", G_CHAIN
    event_types = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, EVENT_APPLICATION)
    requires = ("entity", "other detectors' signals", "device registry or correlations to link app ↔ network")

    def _linked_entities(self, ctx):
        f, ev = ctx.f, ctx.event
        ents, links = {f.entity_key}, []
        if f.entity_kind == "device" and f.device_key:
            dev = RegisteredDevice.query.filter_by(device_key=f.device_key).first()
            if dev and dev.owner_user_id:
                ents.add(f"user:{dev.owner_user_id}")
                links.append(f"device {f.device_key} registered to user {dev.owner_user_id}")
        if f.entity_kind == "user" and f.user_id:
            for dev in RegisteredDevice.query.filter_by(owner_user_id=f.user_id, active=True).all():
                ents.add(f"device:{dev.device_key}")
                links.append(f"user {f.user_id} owns registered device {dev.device_key}")
        corr = EventCorrelation.query.filter(
            db.or_(EventCorrelation.application_event_id == ev.id, EventCorrelation.network_event_id == ev.id)).all()
        for c in corr:
            other = c.network_event if c.application_event_id == ev.id else c.application_event
            if other is not None and other.entity_key:
                ents.add(other.entity_key)
                links.append(f"correlation {c.correlation_uuid} ({c.method}, {c.confidence})")
        return ents, links

    def evaluate(self, ctx):
        f = ctx.f
        if not f.entity_key:
            return self.not_evaluated("No entity — observations cannot be linked.", missing=["entity"])
        ents, links = self._linked_entities(ctx)
        W = float(ctx.cfg("D24_WINDOW_S"))
        since = naive_utc(ctx.ts - W)
        rows = (DetectionSignal.query
                .filter(DetectionSignal.entity_key.in_(ents), DetectionSignal.status == "triggered",
                        DetectionSignal.category == "security", DetectionSignal.created_at >= since,
                        DetectionSignal.detector_id != self.id)
                .order_by(DetectionSignal.created_at.desc()).limit(500).all())
        stages = {}
        for r in rows:
            st = STAGE_OF.get(r.detector_id)
            if st:
                stages.setdefault(st, set()).add(f"{r.detector_id}:{r.signal_uuid}")
        for det_id, res in ctx.results.items():
            if res.status == TRIGGERED and STAGE_OF.get(det_id):
                stages.setdefault(STAGE_OF[det_id], set()).add(f"{det_id}:this-event")
        observed = {"entities": sorted(ents), "links": links, "stages": {k: sorted(v)[:10] for k, v in stages.items()},
                    "window_s": W, "entity_key": f.entity_key}
        need = int(ctx.cfg("D24_MIN_STAGES"))
        avail = {}
        if f.entity_kind == "addr":
            avail = {"partial": True, "application_link": "address-level entity — no device registry or correlation to link application activity"}
        if len(stages) < need:
            return self.clear(f"{len(stages)} stage(s) observed for linked entities (need {need}).",
                              observed=observed, availability=avail, threshold={"min_stages": need})
        sev = "CRITICAL" if len(stages) >= need + 1 and "exfiltration" in stages else "HIGH"
        day = int(ctx.ts // 86400)
        return self.triggered(sev, f"{len(stages)} stages linked within {int(W // 3600)} h: " + ", ".join(sorted(stages)) +
                              (" via " + "; ".join(links) if links else " (same entity)") + ".",
                              observed=observed, availability=avail, threshold={"min_stages": need},
                              dedup_scope=f"D24:{','.join(sorted(ents))}:{day}")


class DeviceSilent(Detector):
    id, name, version, group = "D11", "Device goes silent / VPN gap", "1.0", G_HEALTH
    category = "security"
    event_types = ("sweep",)
    requires = ("registered devices with expected_interval_s", "live collector or agent heartbeats", "VPN state (heartbeat telemetry, optional)")

    def evaluate(self, ctx):  # pragma: no cover - sweep only
        return self.not_evaluated("Evaluated by the telemetry sweep.")

    def sweep(self, ctx):
        from services.live_collector import LiveCollector
        status = LiveCollector.get_instance().get_status()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        out = []
        devices = RegisteredDevice.query.filter(RegisteredDevice.active.is_(True),
                                                RegisteredDevice.expected_interval_s.isnot(None)).all()
        for d in devices:
            exp = int(d.expected_interval_s)
            obs = {"entity_key": f"device:{d.device_key}", "expected_interval_s": exp,
                   "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                   "last_heartbeat_at": d.last_heartbeat_at.isoformat() if d.last_heartbeat_at else None,
                   "vpn_connected": d.vpn_connected, "collector_mode": status["mode"]}
            hb_fresh = d.last_heartbeat_at is not None and (now - d.last_heartbeat_at).total_seconds() <= exp
            uses_heartbeat = d.last_heartbeat_at is not None
            vpn_note = None
            if d.vpn_connected is False and d.vpn_state_at:
                vpn_note = f"VPN reported disconnected at {d.vpn_state_at.isoformat()}"
            avail = {} if d.vpn_state_at else {"vpn": "no VPN telemetry for this device — VPN gap not evaluated"}
            if uses_heartbeat:
                if hb_fresh:
                    out.append(self.clear("Heartbeat within the expected interval.", observed=obs, availability=avail))
                    continue
                gap = (now - d.last_heartbeat_at).total_seconds()
                sev = "MEDIUM" if vpn_note else "LOW"
                out.append(self.triggered(sev, f"No heartbeat from {d.device_key} for {int(gap)} s (expected every {exp} s)"
                                               + (f"; {vpn_note}" if vpn_note else "") + ".",
                                          observed={**obs, "silence_s": int(gap)}, availability=avail,
                                          dedup_scope=f"D11:{d.device_key}:hb:{d.last_heartbeat_at.isoformat()}"))
                continue
            # Network observation expectation: only meaningful while the collector really captures.
            if status["mode"] != "live":
                out.append(self.not_evaluated(f"Collector is {status['mode']} — device silence cannot be told apart "
                                              "from a collection outage.", observed=obs, availability=avail))
                continue
            if status.get("uptime_seconds", 0) < exp:
                out.append(self.not_evaluated("Collector has not been capturing for a full expected interval yet.",
                                              observed=obs, availability=avail))
                continue
            if status.get("packets_captured", 0) == 0:
                out.append(self.not_evaluated("Collector is live but has observed no packets (interface failure?) — see D25.",
                                              observed=obs, availability=avail))
                continue
            ref = d.last_seen_at
            started = now - timedelta(seconds=status["uptime_seconds"])
            if ref is None or ref < started:
                ref_desc, gap = "since capture started", status["uptime_seconds"]
            else:
                ref_desc, gap = "", (now - ref).total_seconds()
            if gap <= exp:
                out.append(self.clear("Device observed within the expected interval.", observed=obs, availability=avail))
                continue
            out.append(self.triggered("LOW", f"{d.device_key} not observed on the network for {int(gap)} s {ref_desc} "
                                             f"(expected every {exp} s) while capture was healthy"
                                             + (f"; {vpn_note}" if vpn_note else "") + ".",
                                      observed={**obs, "silence_s": int(gap)}, availability=avail,
                                      dedup_scope=f"D11:{d.device_key}:net:{obs['last_seen_at']}"))
        if not devices:
            out.append(self.not_evaluated("No registered device has an expected observation interval.",
                                          missing=["expected_interval_s"]))
        return out


class TelemetryHealth(Detector):
    id, name, version, group = "D25", "Telemetry health", "1.0", G_HEALTH
    category = "telemetry_health"     # never creates security alerts
    event_types = ("sweep",)
    requires = ("collector status", "application-event outbox")
    STATE = "d25_last"

    def evaluate(self, ctx):  # pragma: no cover - sweep only
        return self.not_evaluated("Evaluated by the telemetry sweep.")

    def sweep(self, ctx):
        from services import app_activity
        from services.live_collector import LiveCollector
        st = LiveCollector.get_instance().get_status()
        hour = int(ctx.now // 3600)
        prev = ctx.baselines.get_state("__system__", self.STATE)
        issues = []
        if st["mode"] == "failed":
            issues.append(("HIGH", "collector_failed", f"Collector failed: {st.get('last_collector_error')}"))
        if st["mode"] == "live":
            seen = st["packets_captured"] + st["packets_dropped"]
            ratio = st["packets_dropped"] / seen if seen else 0.0
            if ratio > float(ctx.cfg("D25_MAX_DROP_RATIO")):
                issues.append(("MEDIUM", "packets_dropped", f"{st['packets_dropped']} packets dropped ({ratio:.1%}) — "
                                                            "processing cannot keep up with capture"))
            if st["packets_captured"] == 0 and st.get("uptime_seconds", 0) >= 300:
                issues.append(("MEDIUM", "interface_silent", f"No packets observed on {st.get('active_interface')} for "
                                                             f"{int(st['uptime_seconds'])} s"))
        if st["processing_errors"] > int(prev.get("processing_errors", 0)):
            issues.append(("LOW", "processing_errors", f"{st['processing_errors'] - int(prev.get('processing_errors', 0))} new "
                                                       f"processing errors (last: {st.get('last_processing_error')})"))
        pending = app_activity.pending_count()
        if pending > int(ctx.cfg("D25_MAX_OUTBOX_PENDING")):
            issues.append(("MEDIUM", "outbox_backlog", f"{pending} application events waiting in the outbox"))
        ctx.baselines.set_state("__system__", self.STATE, {"processing_errors": st["processing_errors"]})
        obs = {"collector_mode": st["mode"], "packets_captured": st["packets_captured"], "packets_dropped": st["packets_dropped"],
               "processing_errors": st["processing_errors"], "outbox_pending": pending, "entity_key": "__system__"}
        if not issues:
            return [self.clear("Telemetry pipeline healthy.", observed=obs)]
        return [self.triggered(sev, msg, observed={**obs, "issue": code}, dedup_scope=f"D25:{code}:{hour}")
                for sev, code, msg in issues]
