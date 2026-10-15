"""
Temporal detectors: D4 unusual time, D9 spread-out leaking, D10 sudden behaviour change.

D4 keeps a per-entity histogram of *active hours* (an hour counts once, however many
events occur in it) in DETECTION_TIMEZONE, and evaluates the first activity of each hour.

D9 and D10 share a per-entity daily roll-up (outbound bytes, flows, destinations with
bytes, active hours). When the first event of a new day arrives, the previous day is
closed: its features become baseline samples (untrusted if the day contained flagged
traffic) and are compared with the trailing daily baseline.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from core.models import EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD
from services.detection.base import G_BEHAVIOUR, G_EXFIL, Detector
from services.detection.detectors.volume import mb

NET = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
MAX_DAILY_DESTS = 500


def local_time(ctx, ts):
    try:
        tz = ZoneInfo(ctx.cfg("DETECTION_TIMEZONE") or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(tz)


def is_activity(f) -> bool:
    """Activity attributable to the entity itself (it initiated / performed it)."""
    if f.event_type == EVENT_APPLICATION:
        return True
    return bool(f.initiator_internal)


class UnusualTime(Detector):
    id, name, version, group = "D4", "Unusual time", "1.0", G_BEHAVIOUR
    event_types = NET + (EVENT_APPLICATION,)
    requires = ("entity", f"≥D4_MIN_ACTIVE_HOURS active hours over ≥D4_MIN_DAYS days", "DETECTION_TIMEZONE")
    STATE = "d4_hours"

    def evaluate(self, ctx):
        f = ctx.f
        if not f.entity_key:
            return self.not_evaluated("No entity (identity unknown).", missing=["entity"])
        if not is_activity(f):
            return self.clear("Not activity initiated by this entity.")
        lt = local_time(ctx, ctx.ts)
        if lt is None:
            return self.not_evaluated(f"Timezone {ctx.cfg('DETECTION_TIMEZONE')!r} unavailable.", missing=["timezone"])
        hour_key, date_key = lt.strftime("%Y-%m-%dT%H"), lt.strftime("%Y-%m-%d")
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        ctx.cache["d4"] = (hour_key, date_key, lt.hour, lt.weekday())
        if st.get("last_hour") == hour_key:
            return self.clear("Entity already active in this hour (evaluated at the hour's first activity).")
        hours = st.get("hours") or [0] * 24
        total, days = sum(hours), int(st.get("days", 0))
        observed = {"local_hour": lt.hour, "weekday": lt.weekday(), "timezone": ctx.cfg("DETECTION_TIMEZONE"),
                    "entity_key": f.entity_key}
        need_h, need_d = int(ctx.cfg("D4_MIN_ACTIVE_HOURS")), int(ctx.cfg("D4_MIN_DAYS"))
        if total < need_h or days < need_d:
            return self.not_evaluated(f"Activity profile too short ({total} active hours over {days} days; "
                                      f"need {need_h} over {need_d}).", observed=observed,
                                      baseline={"active_hours": total, "days": days})
        frac = hours[lt.hour] / total
        wd = st.get("weekdays") or [0] * 7
        wd_frac = wd[lt.weekday()] / max(sum(wd), 1)
        observed.update(hour_share=round(frac, 4), weekday_share=round(wd_frac, 4))
        base = {"active_hours": total, "days": days, "hour_histogram": hours, "weekday_histogram": wd}
        thr = {"rare_fraction": ctx.cfg("D4_RARE_FRACTION")}
        if frac >= float(thr["rare_fraction"]):
            return self.clear(f"Hour {lt.hour:02d}:00 accounts for {frac:.1%} of this entity's active hours.",
                              observed=observed, baseline=base, threshold=thr)
        big = (f.outbound_bytes or 0) >= float(ctx.cfg("D1_MIN_OUTBOUND_BYTES"))
        sev = "MEDIUM" if big else "LOW"
        return self.triggered(sev, f"Activity at {lt.hour:02d}:00 {ctx.cfg('DETECTION_TIMEZONE')} — only {frac:.1%} of this "
                                   f"entity's {total} active hours fall in that hour" + (f"; {mb(f.outbound_bytes)} MB outbound." if big else "."),
                              observed=observed, baseline=base, threshold=thr,
                              dedup_scope=f"D4:{f.entity_key}:{hour_key}")

    def commit(self, ctx, result, flagged):
        if "d4" not in ctx.cache or not ctx.f.entity_key or flagged:
            return
        hour_key, date_key, hour, weekday = ctx.cache["d4"]
        st = ctx.baselines.get_state(ctx.f.entity_key, self.STATE)
        if st.get("last_hour") == hour_key:
            return
        hours = st.get("hours") or [0] * 24
        wd = st.get("weekdays") or [0] * 7
        hours[hour] += 1
        if st.get("last_date") != date_key:
            st["days"] = int(st.get("days", 0)) + 1
            wd[weekday] += 1
        st.update(hours=hours, weekdays=wd, last_hour=hour_key, last_date=date_key)
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, st)


# ---------------------------------------------------------------------- daily roll-up
ROLLUP_STATE = "daily_rollup"
DAILY_METRICS = ("daily_outbound_bytes", "daily_flows", "daily_destinations", "daily_active_hours", "daily_wide_rare_dests")


def daily_rollup(ctx):
    """Compute (once per event) the closed previous day, if any, and the updated open day."""
    if "rollup" in ctx.cache:
        return ctx.cache["rollup"]
    f = ctx.f
    res = {"closed": None, "open": None, "error": None}
    ctx.cache["rollup"] = res
    if not f.entity_key or f.event_type not in NET or not is_activity(f):
        return res
    lt = local_time(ctx, ctx.ts)
    if lt is None:
        res["error"] = "timezone unavailable"
        return res
    day, hour = lt.strftime("%Y-%m-%d"), lt.hour
    st = ctx.baselines.get_state(f.entity_key, ROLLUP_STATE)
    if st and st.get("day") and day < st["day"]:
        res["error"] = "out-of-order event older than the open day"
        return res
    if not st or st.get("day") != day:
        res["closed"] = st if st and st.get("day") else None
        st = {"day": day, "out": 0.0, "flows": 0, "dests": {}, "hours": [], "tainted": False}
    st = {**st, "dests": dict(st.get("dests", {})), "hours": list(st.get("hours", []))}
    st["flows"] += 1
    st["out"] += float(f.outbound_bytes or 0)
    if f.destination and f.external_ip:
        if f.destination in st["dests"] or len(st["dests"]) < MAX_DAILY_DESTS:
            st["dests"][f.destination] = st["dests"].get(f.destination, 0) + float(f.outbound_bytes or 0)
    if hour not in st["hours"]:
        st["hours"].append(hour)
    res["open"] = st

    def persist(flagged):
        new = dict(res["open"])
        if flagged:
            new["tainted"] = True
        ctx.baselines.set_state(f.entity_key, ROLLUP_STATE, new)
        closed = res["closed"]
        if closed:
            feats = closed_features(ctx, closed)
            trusted = not closed.get("tainted", False)
            day_ts = datetime.fromisoformat(closed["day"]).replace(tzinfo=timezone.utc).timestamp()
            for metric in DAILY_METRICS:
                ctx.baselines.add_sample(f.entity_key, metric, feats[metric], day_ts, f"day:{closed['day']}", None, trusted)
    ctx.after_commit.append(persist)
    return res


def closed_features(ctx, day_state):
    if "closed_feats" in ctx.cache:
        return ctx.cache["closed_feats"]
    per_dest_min = float(ctx.cfg("D9_MIN_BYTES_PER_DEST"))
    wide = [d for d, b in day_state.get("dests", {}).items() if b >= per_dest_min]
    rare = [d for d in wide if ctx.baselines.destination_popularity(d) <= 1]
    feats = {
        "daily_outbound_bytes": float(day_state.get("out", 0)),
        "daily_flows": float(day_state.get("flows", 0)),
        "daily_destinations": float(len(day_state.get("dests", {}))),
        "daily_active_hours": float(len(day_state.get("hours", []))),
        "daily_wide_rare_dests": float(len(rare)),
        "_rare_destinations": sorted(rare)[:50],
        "_upload_destinations": len(wide),
    }
    ctx.cache["closed_feats"] = feats
    return feats


class SpreadOutLeak(Detector):
    id, name, version, group = "D9", "Spread-out leaking", "1.0", G_EXFIL
    event_types = NET
    requires = ("entity daily roll-up", "organisation destination popularity", f"≥D9_MIN_DAYS closed days")

    def evaluate(self, ctx):
        f = ctx.f
        if not f.entity_key:
            return self.not_evaluated("No entity — identity-specific analysis unavailable.", missing=["entity"])
        r = daily_rollup(ctx)
        if r["error"]:
            return self.not_evaluated(f"Daily roll-up unavailable: {r['error']}.")
        if not r["closed"]:
            return self.not_evaluated("Evaluated when the entity's current day closes.")
        feats = closed_features(ctx, r["closed"])
        x = feats["daily_wide_rare_dests"]
        observed = {"day": r["closed"]["day"], "rare_upload_destinations": feats["_rare_destinations"],
                    "rare_count": int(x), "upload_destinations": feats["_upload_destinations"],
                    "entity_key": f.entity_key, "entity_kind": f.entity_kind,
                    "note": None if f.entity_kind != "addr" else "Address-level analysis: identity not established."}
        thr = {"min_destinations": ctx.cfg("D9_MIN_DESTINATIONS"), "min_bytes_per_destination": ctx.cfg("D9_MIN_BYTES_PER_DEST")}
        if x < float(thr["min_destinations"]):
            return self.clear(f"{int(x)} rare destinations received uploads that day.", observed=observed, threshold=thr)
        st = ctx.baselines.stats(f.entity_key, "daily_wide_rare_dests", ctx.ts, min_samples=int(ctx.cfg("D9_MIN_DAYS")))
        if st is None:
            return self.not_evaluated("Insufficient daily history for this entity.", observed=observed, threshold=thr)
        z = st.robust_z(x, floor=1.0)
        zt = float(ctx.cfg("D10_Z"))
        observed["robust_z"] = round(z, 2)
        if z < zt:
            return self.clear("Spread of upload destinations typical for this entity.", observed=observed,
                              baseline=st.as_dict(), threshold={**thr, "robust_z": zt})
        sev = "HIGH" if x >= 2 * float(thr["min_destinations"]) else "MEDIUM"
        return self.triggered(sev, f"On {observed['day']} uploads ≥{mb(float(thr['min_bytes_per_destination']))} MB went to "
                                   f"{int(x)} destinations no other entity uses (robust z {z:.1f}).",
                              observed=observed, baseline=st.as_dict(), threshold={**thr, "robust_z": zt},
                              dedup_scope=f"D9:{f.entity_key}:{observed['day']}")


class SuddenChange(Detector):
    id, name, version, group = "D10", "Sudden behaviour change", "1.0", G_BEHAVIOUR
    event_types = NET
    requires = ("entity daily roll-up", f"≥D10_MIN_DAYS closed days per feature")
    FEATURES = ("daily_outbound_bytes", "daily_flows", "daily_destinations", "daily_active_hours")

    def evaluate(self, ctx):
        f = ctx.f
        if not f.entity_key:
            return self.not_evaluated("No entity.", missing=["entity"])
        r = daily_rollup(ctx)
        if r["error"]:
            return self.not_evaluated(f"Daily roll-up unavailable: {r['error']}.")
        if not r["closed"]:
            return self.not_evaluated("Evaluated when the entity's current day closes.")
        feats = closed_features(ctx, r["closed"])
        zt = float(ctx.cfg("D10_Z"))
        floors = {"daily_outbound_bytes": 1024 * 1024.0, "daily_flows": 5.0, "daily_destinations": 2.0, "daily_active_hours": 1.0}
        zs, base, missing = {}, {}, []
        for m in self.FEATURES:
            st = ctx.baselines.stats(f.entity_key, m, ctx.ts, min_samples=int(ctx.cfg("D10_MIN_DAYS")))
            if st is None:
                missing.append(m)
                continue
            zs[m] = round(st.robust_z(feats[m], floor=floors[m]), 2)
            base[m] = st.as_dict()
        observed = {"day": r["closed"]["day"], **{m: feats[m] for m in self.FEATURES}, "robust_z": zs,
                    "entity_key": f.entity_key}
        if not zs:
            return self.not_evaluated("Insufficient daily history for every feature.", missing=missing, observed=observed)
        strong = [m for m, z in zs.items() if abs(z) >= zt]
        thr = {"robust_z": zt, "rule": "≥2 features beyond z, or one beyond 2z"}
        avail = {"features_without_baseline": missing} if missing else {}
        if len(strong) >= 2 or any(abs(z) >= 2 * zt for z in zs.values()):
            return self.triggered("MEDIUM", f"Behaviour on {observed['day']} departs from the entity's baseline in "
                                            f"{', '.join(strong) or 'one feature'} (robust z {zs}).",
                                  observed=observed, baseline=base, threshold=thr, availability=avail,
                                  dedup_scope=f"D10:{f.entity_key}:{observed['day']}")
        return self.clear("Daily behaviour within baseline.", observed=observed, baseline=base, threshold=thr,
                          availability=avail)
