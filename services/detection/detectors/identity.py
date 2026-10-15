"""
Identity & authentication detectors (application evidence from server-side sessions):
D13 two sessions at once, D14 unusual connection source, D15 two devices one identity,
D27 authentication anomalies.

Login, failed-login and logout are recorded as application_activity events by
services/auth_sessions.py. Identity always comes from the server-side session or the
account that the submitted username resolved to — never from client fields.
"""
import ipaddress
from datetime import datetime, timezone

from core.database import db
from core.models import EVENT_APPLICATION, ORG_ENTITY, AuthSession, Event, RegisteredDevice
from core.timeutil import naive_utc
from services.detection import enrichment, identity
from services.detection.base import G_IDENTITY, Detector

APP = (EVENT_APPLICATION,)


def network_prefix(ip):
    """/24 for IPv4, /48 for IPv6 — 'materially different source' granularity."""
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False))


class ConcurrentSessions(Detector):
    id, name, version, group = "D13", "Two sessions at once", "1.0", G_IDENTITY
    event_types = APP
    requires = ("persistent auth sessions (auth_sessions)", "login events with source address")

    def evaluate(self, ctx):
        f = ctx.f
        if f.action != "login" or f.outcome != "success":
            return self.clear("Not a successful login.")
        sref = f.app.get("session_ref")
        if not f.user_id or sref is None:
            return self.not_evaluated("Login without a tracked session.", missing=["session_ref"])
        this_prefix = network_prefix(f.src_ip)
        if this_prefix is None:
            return self.not_evaluated("Source address unknown for this login.", missing=["src_ip"])
        at = naive_utc(ctx.ts)
        grace = float(ctx.cfg("D13_OVERLAP_GRACE_S"))
        others = AuthSession.query.filter(
            AuthSession.user_id == f.user_id, AuthSession.id != sref, AuthSession.ended_at.is_(None),
            AuthSession.expires_at > at, AuthSession.last_seen_at >= naive_utc(ctx.ts - grace),
        ).all()
        geo_ok = enrichment.geoip.available
        here_cc = (enrichment.geoip.lookup(f.src_ip) or {}).get("country") if geo_ok else None
        different = []
        for s in others:
            p = network_prefix(s.source_ip)
            if p and p != this_prefix:
                cc = (enrichment.geoip.lookup(s.source_ip) or {}).get("country") if geo_ok else None
                different.append({"session_id": s.id, "prefix": p, "country": cc,
                                  "created_at": s.created_at.isoformat(), "last_seen_at": s.last_seen_at.isoformat()})
        observed = {"user_id": f.user_id, "login_prefix": this_prefix, "login_country": here_cc,
                    "concurrent_sessions": len(others), "from_other_networks": different, "entity_key": f.entity_key}
        avail = {} if geo_ok else {"partial": True, "geoip": "unavailable — network-prefix comparison only"}
        if not different:
            return self.clear("No concurrent session from a different network (same-network concurrency is normal).",
                              observed=observed, availability=avail)
        cross_country = any(d["country"] and here_cc and d["country"] != here_cc for d in different)
        sev = "HIGH" if cross_country else "MEDIUM"
        return self.triggered(sev, f"User {f.user_id} logged in from {this_prefix} while {len(different)} other session(s) "
                                   f"from different network(s) were active within {int(grace)} s"
                                   + (" in another country" if cross_country else "") + ". VPN/mobile switching can also do this.",
                              observed=observed, availability=avail, threshold={"overlap_grace_s": grace})


class UnusualSource(Detector):
    id, name, version, group = "D14", "Unusual connection source", "1.0", G_IDENTITY
    event_types = APP
    requires = ("successful login events", f"≥D14_MIN_LOGINS prior logins", "GeoIP/ASN (optional)")
    STATE, ORG = "d14_sources", "d14_prefix_users"

    def evaluate(self, ctx):
        f = ctx.f
        if f.action != "login" or f.outcome != "success":
            return self.clear("Not a successful login.")
        if not f.user_id:
            return self.not_evaluated("No authenticated user.", missing=["user_id"])
        prefix = network_prefix(f.src_ip)
        if prefix is None:
            return self.not_evaluated("Source address unknown.", missing=["src_ip"])
        geo = enrichment.geoip.lookup(f.src_ip) if enrichment.geoip.available else None
        cc, asn = (geo or {}).get("country"), (geo or {}).get("asn")
        ctx.cache["d14"] = (prefix, cc, asn)
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        org = ctx.baselines.get_state(ORG_ENTITY, self.ORG)
        total = int(st.get("total", 0))
        sharing = len((org.get("prefixes") or {}).get(prefix, []))
        observed = {"prefix": prefix, "country": cc, "asn": asn, "prior_logins": total, "users_sharing_prefix": sharing,
                    "entity_key": f.entity_key}
        avail = {} if geo is not None else {"partial": True, "geoip": "unavailable — prefix comparison only"}
        if total < int(ctx.cfg("D14_MIN_LOGINS")):
            return self.not_evaluated(f"Too few prior logins ({total}).", observed=observed, availability=avail)
        findings = []
        if cc and cc not in st.get("countries", {}):
            findings.append(("MEDIUM", f"first login from country {cc}"))
        if asn is not None and str(asn) not in st.get("asns", {}):
            findings.append(("LOW", f"first login from AS{asn}"))
        if prefix not in st.get("prefixes", {}):
            if sharing >= 3:
                observed["note"] = f"new for this user but shared by {sharing} other users (corporate NAT/VPN egress?)"
            else:
                findings.append(("LOW", f"first login from network {prefix}"))
        if not findings:
            return self.clear("Login source previously used by this user.", observed=observed, availability=avail)
        sev = "MEDIUM" if any(s == "MEDIUM" for s, _ in findings) else "LOW"
        return self.triggered(sev, "Unusual login source: " + "; ".join(t for _, t in findings) +
                              ". Geolocation is approximate and VPNs/proxies change apparent location.",
                              observed=observed, availability=avail, evidence_only=sev == "LOW")

    def commit(self, ctx, result, flagged):
        if "d14" not in ctx.cache or flagged:
            return
        prefix, cc, asn = ctx.cache["d14"]
        st = ctx.baselines.get_state(ctx.f.entity_key, self.STATE)
        st["total"] = int(st.get("total", 0)) + 1
        for k, v in (("prefixes", prefix), ("countries", cc), ("asns", str(asn) if asn is not None else None)):
            if v:
                d = st.setdefault(k, {})
                d[v] = d.get(v, 0) + 1
                if len(d) > 200:
                    st[k] = dict(sorted(d.items(), key=lambda kv: -kv[1])[:200])
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, st)
        org = ctx.baselines.get_state(ORG_ENTITY, self.ORG)
        users = org.setdefault("prefixes", {}).setdefault(prefix, [])
        if ctx.f.entity_key not in users and len(users) < 50:
            users.append(ctx.f.entity_key)
            ctx.baselines.set_state(ORG_ENTITY, self.ORG, org)


class TwoDevices(Detector):
    id, name, version, group = "D15", "Two devices, one identity", "1.0", G_IDENTITY
    event_types = APP
    requires = ("device registry with address bindings", "application events with client address")
    STATE = "d15_devices"

    def evaluate(self, ctx):
        f = ctx.f
        if not f.user_id:
            return self.not_evaluated("No authenticated user.", missing=["user_id"])
        if RegisteredDevice.query.count() == 0:
            return self.not_evaluated("No registered devices — user-to-device mapping unavailable.", missing=["device_registry"])
        res = identity.resolve_device(f.src_ip, ctx.ts)
        if res is None or res.get("ambiguous"):
            return self.not_evaluated("Client address is not bound to exactly one registered device.",
                                      missing=["device_binding"], observed={"src_ip": f.src_ip})
        dev = res["device_key"]
        W = float(ctx.cfg("D15_WINDOW_S"))
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        recent = {k: v for k, v in (st.get("recent") or {}).items() if ctx.ts - v <= W and k != dev}
        ctx.cache["d15"] = dev
        owned = {d.device_key for d in identity.devices_of_user(f.user_id)}
        observed = {"device": dev, "device_owner": res["owner_user_id"], "user_devices": sorted(owned),
                    "other_devices_in_window": sorted(recent), "window_s": W, "entity_key": f.entity_key,
                    "binding": res["binding_source"]}
        avail = {"behavioural_divergence": "not implemented — needs per-device behaviour history"}
        not_owned = [d for d in list(recent) + [dev] if d not in owned]
        if recent and not_owned:
            return self.triggered("MEDIUM", f"User {f.user_id} active from {len(recent) + 1} devices within {int(W)} s, "
                                            f"including {', '.join(not_owned)} not registered to them.",
                                  observed=observed, availability=avail)
        if res["owner_user_id"] not in (None, f.user_id):
            return self.triggered("LOW", f"User {f.user_id} active on {dev}, which is registered to user {res['owner_user_id']}.",
                                  observed=observed, availability=avail, evidence_only=True)
        return self.clear("Device use consistent with the registry.", observed=observed, availability=avail)

    def commit(self, ctx, result, flagged):
        dev = ctx.cache.get("d15")
        if not dev:
            return
        st = ctx.baselines.get_state(ctx.f.entity_key, self.STATE)
        recent = {k: v for k, v in (st.get("recent") or {}).items() if ctx.ts - v <= 86400}
        recent[dev] = ctx.ts
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, {"recent": recent})


class AuthAnomalies(Detector):
    id, name, version, group = "D27", "Authentication anomalies", "1.0", G_IDENTITY
    event_types = APP
    requires = ("login / login_failed application events",)

    def evaluate(self, ctx):
        f = ctx.f
        if f.action not in ("login", "login_failed"):
            return self.clear("Not an authentication event.")
        W = float(ctx.cfg("D27_WINDOW_S"))
        since = naive_utc(ctx.ts - W)
        until = naive_utc(ctx.ts + 1)
        base_q = Event.query.filter(Event.event_type == EVENT_APPLICATION, Event.action == "login_failed",
                                    Event.event_time >= since, Event.event_time <= until)
        thr = {"window_s": W, "account_failures": ctx.cfg("D27_ACCOUNT_FAILURES"), "spray_accounts": ctx.cfg("D27_SPRAY_ACCOUNTS")}
        findings = []
        acct_fail = base_q.filter(Event.user_id == f.user_id).count() if f.user_id else 0
        if f.action == "login" and f.outcome == "success" and acct_fail >= int(thr["account_failures"]):
            findings.append(("MEDIUM", f"successful login after {acct_fail} failures for this account within {int(W)} s"))
        if f.action == "login_failed":
            if f.user_id and acct_fail >= int(thr["account_failures"]):
                findings.append(("MEDIUM" if acct_fail >= 2 * int(thr["account_failures"]) else "LOW",
                                 f"{acct_fail} failed logins for one account within {int(W)} s"))
            if f.src_ip:
                rows = base_q.filter(Event.src_ip == f.src_ip).limit(1000).all()
                targets = {(r.user_id if r.user_id else r.details.get("account_ref")) for r in rows}
                targets.discard(None)
                if len(targets) >= int(thr["spray_accounts"]):
                    findings.append(("MEDIUM", f"{len(targets)} different accounts failed from {f.src_ip} within {int(W)} s "
                                               "(password spraying pattern)"))
        observed = {"action": f.action, "account_failures_in_window": acct_fail, "src_ip": f.src_ip,
                    "user_id": f.user_id, "entity_key": f.entity_key or (f"src:{f.src_ip}" if f.src_ip else None)}
        if not findings:
            return self.clear("Authentication pattern below thresholds.", observed=observed, threshold=thr)
        sev = "MEDIUM" if any(s == "MEDIUM" for s, _ in findings) else "LOW"
        bucket = int(ctx.ts // W)
        return self.triggered(sev, "; ".join(t for _, t in findings) + ".", observed=observed, threshold=thr,
                              dedup_scope=f"D27:{f.user_id or f.src_ip}:{f.action}:{bucket}")
