"""
Volume detectors: D1 large upload, D5 upload-heavy, D6 long upload session,
D7 slow leaking (CUSUM over EWMA), D16 internal bulk download (application evidence).
"""
import math
from typing import Optional

from core.models import EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD
from services.detection import enrichment
from services.detection.base import G_EXFIL, Detector

NET = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
TRANSFER_MIN_BYTES = 64 * 1024       # per-flow baselines describe transfers, not keep-alives


def mb(x) -> float:
    return round((x or 0) / (1024 * 1024), 3)


def outbound_prereq(det: Detector, f, *, need_inbound=False):
    """Shared not_evaluated / clear gating for detectors that need outbound volume."""
    if not f.completed:
        return det.not_evaluated("Flow not complete — volume detectors only evaluate completed flows.",
                                 missing=["completed_flow"])
    if f.org_direction == "unknown":
        return det.not_evaluated("Organisation direction unknown (endpoint addresses not classifiable).",
                                 missing=["org_direction"])
    if f.org_direction in ("internal", "external"):
        return det.clear(f"No internal→external path ({f.org_direction} traffic).")
    if f.outbound_bytes is None or (need_inbound and f.inbound_bytes is None):
        return det.not_evaluated("Missing directional byte counts for this event.",
                                 missing=["outbound_bytes"] + (["inbound_bytes"] if need_inbound else []))
    if not f.entity_key:
        return det.not_evaluated("No internal endpoint entity to compare against.", missing=["entity"])
    return None


class LargeUpload(Detector):
    id, name, version, group = "D1", "Large upload", "1.0", G_EXFIL
    event_types = NET
    requires = ("completed flow / record", "outbound bytes (org-oriented)", f"≥BASELINE_MIN_SAMPLES prior transfers")
    METRIC = "flow_outbound_bytes"

    def evaluate(self, ctx):
        f = ctx.f
        gate = outbound_prereq(self, f)
        if gate:
            return gate
        x = f.outbound_bytes
        floor = float(ctx.cfg("D1_MIN_OUTBOUND_BYTES"))
        observed = {"outbound_bytes": x, "outbound_mb": mb(x), "destination": f.destination, "entity_key": f.entity_key,
                    "entity_kind": f.entity_kind}
        if x < floor:
            return self.clear(f"Outbound {mb(x)} MB is below the {mb(floor)} MB floor.", observed=observed)
        st = ctx.baselines.stats(f.entity_key, self.METRIC, ctx.ts)
        if st is None:
            n = ctx.baselines.sample_count(f.entity_key, self.METRIC, ctx.ts)
            return self.not_evaluated(f"Insufficient baseline: {n} prior transfers (< {ctx.cfg('BASELINE_MIN_SAMPLES')}).",
                                      observed=observed, baseline={"samples": n})
        z = st.robust_z(x, floor=float(TRANSFER_MIN_BYTES))
        zt = float(ctx.cfg("ROBUST_Z_THRESHOLD"))
        threshold = {"robust_z": zt, "min_outbound_bytes": floor}
        observed["robust_z"] = round(z, 2)
        if z < zt:
            return self.clear(f"Outbound {mb(x)} MB is within the entity's range (robust z {z:.1f}).",
                              observed=observed, baseline=st.as_dict(), threshold=threshold)
        approved = enrichment.policy.matches_list("approved_bulk_destinations", f.sni, f.external_ip)
        if approved:
            return self.clear(f"Large transfer to an approved bulk destination ({approved}).",
                              observed={**observed, "approved_match": approved}, baseline=st.as_dict(), threshold=threshold)
        sev = "HIGH" if (x >= float(ctx.cfg("D1_HIGH_OUTBOUND_BYTES")) or z >= 2 * zt) else "MEDIUM"
        note = " (baseline MAD is 0; 5% of the median used as scale)" if st.mad_zero else ""
        return self.triggered(sev, f"{mb(x)} MB sent to {f.destination}, robust z {z:.1f} vs this entity's median "
                                   f"{mb(st.median)} MB over {st.n} transfers{note}.",
                              observed=observed, baseline=st.as_dict(), threshold=threshold,
                              evidence=[f"outbound_bytes={int(x)}", f"baseline_median={int(st.median)}", f"robust_z={z:.2f}"])

    def commit(self, ctx, result, flagged):
        f = ctx.f
        if f.entity_key and f.outbound_bytes is not None and f.outbound_bytes >= TRANSFER_MIN_BYTES and f.completed:
            ctx.baselines.add_sample(f.entity_key, self.METRIC, f.outbound_bytes, ctx.ts, ctx.sample_key,
                                     ctx.event.id, trusted=not flagged)


class UploadHeavy(Detector):
    id, name, version, group = "D5", "Upload-heavy activity", "1.0", G_EXFIL
    event_types = NET
    requires = ("outbound and inbound bytes (org-oriented)", "ratio baseline")
    METRIC = "flow_upload_log2_ratio"

    @staticmethod
    def log_ratio(out, inn) -> float:
        # +1 on both sides: defined for zero inbound and zero outbound, no division by zero.
        return math.log2((out + 1.0) / (inn + 1.0))

    def evaluate(self, ctx):
        f = ctx.f
        gate = outbound_prereq(self, f, need_inbound=True)
        if gate:
            return gate
        out, inn = f.outbound_bytes, f.inbound_bytes
        r = self.log_ratio(out, inn)
        observed = {"outbound_bytes": out, "inbound_bytes": inn, "log2_ratio": round(r, 3),
                    "ratio": round((out + 1) / (inn + 1), 2), "entity_key": f.entity_key}
        if out < float(ctx.cfg("D5_MIN_OUTBOUND_BYTES")) or r < float(ctx.cfg("D5_MIN_LOG2_RATIO")):
            return self.clear("Upload/download balance below the upload-heavy thresholds.", observed=observed,
                              threshold={"min_log2_ratio": ctx.cfg("D5_MIN_LOG2_RATIO"), "min_outbound_bytes": ctx.cfg("D5_MIN_OUTBOUND_BYTES")})
        st = ctx.baselines.stats(f.entity_key, self.METRIC, ctx.ts)
        if st is None:
            return self.not_evaluated("Insufficient upload/download ratio history for this entity.", observed=observed,
                                      baseline={"samples": ctx.baselines.sample_count(f.entity_key, self.METRIC, ctx.ts)})
        z = st.robust_z(r, floor=0.5)
        zt = float(ctx.cfg("ROBUST_Z_THRESHOLD")) * 2 / 3
        observed["robust_z"] = round(z, 2)
        if z < zt:
            return self.clear(f"Ratio {observed['ratio']}:1 is typical for this entity (robust z {z:.1f}).",
                              observed=observed, baseline=st.as_dict(), threshold={"robust_z": zt})
        sev = "HIGH" if r >= 6 and out >= float(ctx.cfg("D1_MIN_OUTBOUND_BYTES")) else "MEDIUM"
        return self.triggered(sev, f"Upload-heavy flow: {mb(out)} MB out vs {mb(inn)} MB in ({observed['ratio']}:1), "
                                   f"robust z {z:.1f} vs this entity's usual ratio.",
                              observed=observed, baseline=st.as_dict(), threshold={"robust_z": zt},
                              evidence=[f"log2(out+1/in+1)={r:.2f}", f"baseline_median={st.median:.2f}"])

    def commit(self, ctx, result, flagged):
        f = ctx.f
        if f.entity_key and f.completed and f.outbound_bytes is not None and f.inbound_bytes is not None \
                and f.outbound_bytes >= float(ctx.cfg("D5_MIN_OUTBOUND_BYTES")):
            ctx.baselines.add_sample(f.entity_key, self.METRIC, self.log_ratio(f.outbound_bytes, f.inbound_bytes),
                                     ctx.ts, ctx.sample_key, ctx.event.id, trusted=not flagged)


class LongUpload(Detector):
    id, name, version, group = "D6", "Long upload session", "1.0", G_EXFIL
    event_types = NET
    requires = ("completed flow with duration", "outbound bytes", "long-transfer duration baseline")
    METRIC = "long_transfer_duration_s"

    def evaluate(self, ctx):
        f = ctx.f
        gate = outbound_prereq(self, f)
        if gate:
            return gate
        if f.duration is None:
            return self.not_evaluated("Flow duration unavailable.", missing=["duration"])
        out, dur = f.outbound_bytes, f.duration
        thr = {"min_duration_s": ctx.cfg("D6_MIN_DURATION_S"), "min_outbound_bytes": ctx.cfg("D6_MIN_OUTBOUND_BYTES")}
        observed = {"duration_s": round(dur, 1), "outbound_bytes": out,
                    "outbound_throughput_bps": round(8 * out / dur, 1) if dur > 0 else None, "entity_key": f.entity_key,
                    "flow_end_reason": f.end_reason}
        if dur < float(thr["min_duration_s"]) or out < float(thr["min_outbound_bytes"]):
            return self.clear("Duration or outbound volume below long-upload thresholds.", observed=observed, threshold=thr)
        st = ctx.baselines.stats(f.entity_key, self.METRIC, ctx.ts)
        if st is None:
            return self.not_evaluated("Insufficient history of long transfers for this entity.", observed=observed,
                                      baseline={"samples": ctx.baselines.sample_count(f.entity_key, self.METRIC, ctx.ts)},
                                      threshold=thr)
        z = st.robust_z(dur, floor=30.0)
        zt = float(ctx.cfg("ROBUST_Z_THRESHOLD")) * 2 / 3
        observed["robust_z"] = round(z, 2)
        if z < zt:
            return self.clear(f"Session length typical for this entity (robust z {z:.1f}).", observed=observed,
                              baseline=st.as_dict(), threshold={**thr, "robust_z": zt})
        sev = "HIGH" if out >= float(ctx.cfg("D1_HIGH_OUTBOUND_BYTES")) else "MEDIUM"
        note = " (flow segment ended by the active timeout — the session continues)" if f.end_reason == "active_timeout" else ""
        return self.triggered(sev, f"{round(dur)} s upload session sending {mb(out)} MB to {f.destination}, robust z {z:.1f} "
                                   f"vs this entity's long transfers{note}.",
                              observed=observed, baseline=st.as_dict(), threshold={**thr, "robust_z": zt})

    def commit(self, ctx, result, flagged):
        f = ctx.f
        if f.entity_key and f.completed and f.duration and f.duration >= 60 and (f.outbound_bytes or 0) >= 1024 * 1024:
            ctx.baselines.add_sample(f.entity_key, self.METRIC, f.duration, ctx.ts, ctx.sample_key, ctx.event.id,
                                     trusted=not flagged)


class SlowLeak(Detector):
    """
    Hourly outbound totals per entity. Closed buckets feed a one-sided CUSUM against an
    EWMA mean/variance: S = max(0, S + (x − μ)/σ − k), alarm when S ≥ h.
    Buckets that raised an alarm or contained flagged traffic never update μ/σ.
    """
    id, name, version, group = "D7", "Slow leaking", "1.0", G_EXFIL
    event_types = NET
    requires = ("outbound bytes over time", "≥D7_MIN_BUCKETS closed hourly buckets")
    STATE = "d7_cusum"

    def _advance(self, ctx, st, x, bucket):
        B = int(ctx.cfg("D7_BUCKET_S"))
        a, k, h = float(ctx.cfg("D7_EWMA_ALPHA")), float(ctx.cfg("D7_CUSUM_K")), float(ctx.cfg("D7_CUSUM_H"))
        min_n = int(ctx.cfg("D7_MIN_BUCKETS"))
        st = dict(st)
        alarms = []
        closed = [(st["bucket"], st["sum"], st.get("tainted", False))]
        gap = int((bucket - st["bucket"]) / B) - 1
        for i in range(min(max(gap, 0), int(ctx.cfg("D7_MAX_GAP_BUCKETS")))):
            closed.append((st["bucket"] + (i + 1) * B, 0.0, False))
        for start, v, tainted in closed:
            n, mu, var = st.get("n", 0), st.get("mu", 0.0), st.get("var", 0.0)
            alarmed = False
            if n >= min_n:
                sigma = max(math.sqrt(var), 0.1 * mu, 64 * 1024.0)
                s = max(0.0, st.get("S", 0.0) + (v - mu) / sigma - k)
                if s >= h:
                    alarms.append({"bucket_start": start, "bucket_bytes": v, "cusum": round(s, 2),
                                   "ewma_mean": round(mu, 1), "ewma_sigma": round(sigma, 1)})
                    alarmed, s = True, 0.0      # restart after an alarm
                st["S"] = s
            if not alarmed and not tainted:
                if n == 0:
                    mu, var = v, 0.0
                else:
                    d = v - mu
                    mu = mu + a * d
                    var = (1 - a) * (var + a * d * d)
                st.update(n=n + 1, mu=mu, var=var)
        st.update(bucket=bucket, sum=x, tainted=False)
        return st, alarms

    def evaluate(self, ctx):
        f = ctx.f
        gate = outbound_prereq(self, f)
        if gate:
            return gate
        B = int(ctx.cfg("D7_BUCKET_S"))
        bucket = int(ctx.ts // B * B)
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        x = float(f.outbound_bytes)
        observed = {"entity_key": f.entity_key, "bucket_start": bucket, "outbound_bytes": x}
        if not st:
            ctx.cache["d7"] = {"bucket": bucket, "sum": x, "n": 0, "mu": 0.0, "var": 0.0, "S": 0.0}
            return self.not_evaluated("Initialising hourly outbound baseline.", observed=observed, baseline={"closed_buckets": 0})
        if bucket < st["bucket"]:
            return self.not_evaluated("Out-of-order observation older than the current window (not re-applied).",
                                      observed=observed)
        if bucket == st["bucket"]:
            ctx.cache["d7"] = {**st, "sum": st["sum"] + x}
            if st.get("n", 0) < int(ctx.cfg("D7_MIN_BUCKETS")):
                return self.not_evaluated(f"Baseline warming up ({st.get('n', 0)}/{ctx.cfg('D7_MIN_BUCKETS')} hourly buckets).",
                                          observed=observed)
            return self.clear("Hourly window still open; CUSUM evaluated when the window closes.",
                              observed={**observed, "cusum": round(st.get("S", 0.0), 2)})
        new, alarms = self._advance(ctx, st, x, bucket)
        ctx.cache["d7"] = new
        base = {"closed_buckets": new.get("n", 0), "ewma_mean_bytes": round(new.get("mu", 0.0), 1),
                "ewma_sigma_bytes": round(math.sqrt(new.get("var", 0.0)), 1)}
        thr = {"cusum_k": ctx.cfg("D7_CUSUM_K"), "cusum_h": ctx.cfg("D7_CUSUM_H"), "bucket_s": B}
        if alarms:
            a = alarms[-1]
            return self.triggered("MEDIUM", f"Sustained rise in hourly outbound volume: CUSUM {a['cusum']} ≥ {thr['cusum_h']} "
                                            f"(hour bytes {mb(a['bucket_bytes'])} MB vs EWMA {mb(a['ewma_mean'])} MB).",
                                  observed={**observed, "alarms": alarms}, baseline=base, threshold=thr,
                                  dedup_scope=f"D7:{f.entity_key}:{a['bucket_start']}")
        if new.get("n", 0) < int(ctx.cfg("D7_MIN_BUCKETS")):
            return self.not_evaluated(f"Baseline warming up ({new.get('n', 0)}/{ctx.cfg('D7_MIN_BUCKETS')} hourly buckets).",
                                      observed=observed, baseline=base)
        return self.clear(f"CUSUM {round(new.get('S', 0.0), 2)} below {thr['cusum_h']}.",
                          observed={**observed, "cusum": round(new.get("S", 0.0), 2)}, baseline=base, threshold=thr)

    def commit(self, ctx, result, flagged):
        new = ctx.cache.get("d7")
        if new is None or not ctx.f.entity_key:
            return
        if flagged:
            new = {**new, "tainted": True}   # this hour must not train the EWMA baseline
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, new)


class BulkDownload(Detector):
    """Application downloads per user per window. Evidence of collection inside the portal
    only — it does not show that the same bytes left over any network flow."""
    id, name, version, group = "D16", "Internal bulk download", "1.0", G_EXFIL
    event_types = (EVENT_APPLICATION,)
    requires = ("authenticated download events", "per-user download-window baseline")
    STATE = "d16_window"

    def evaluate(self, ctx):
        f = ctx.f
        if f.action != "download":
            return self.clear("Not a download.")
        if f.outcome != "success":
            return self.clear(f"Download {f.outcome}; no data was served.")
        if not f.user_id:
            return self.not_evaluated("No authenticated user on this event.", missing=["user_id"])
        W = int(ctx.cfg("D16_WINDOW_S"))
        bucket = int(ctx.ts // W * W)
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        size = float(f.app.get("size_bytes") or 0)
        shared = f.app.get("location") == "department_shared"
        if st and st.get("bucket") == bucket:
            cur = {**st, "files": st["files"] + 1, "bytes": st["bytes"] + size,
                   "shared": st.get("shared", 0) + int(shared), "personal": st.get("personal", 0) + int(not shared)}
            closing = None
        else:
            closing = st if st and st.get("bucket", 0) < bucket else None
            cur = {"bucket": bucket, "files": 1, "bytes": size, "shared": int(shared), "personal": int(not shared)}
        ctx.cache["d16"] = (cur, closing)
        observed = {"window_start": bucket, "window_s": W, "files": cur["files"], "bytes": cur["bytes"],
                    "shared_files": cur["shared"], "personal_files": cur["personal"], "entity_key": f.entity_key}
        note = "Application downloads only — this does not show the bytes left the organisation."
        thr = {"min_files": ctx.cfg("D16_MIN_FILES"), "min_bytes": ctx.cfg("D16_MIN_BYTES"),
               "policy_max_files": ctx.cfg("D16_POLICY_MAX_FILES")}
        scope = f"D16:{f.entity_key}:{bucket}"
        if cur["files"] >= int(thr["policy_max_files"]):
            return self.triggered("HIGH", f"{cur['files']} files downloaded within {W // 60} min — exceeds the policy "
                                          f"ceiling of {thr['policy_max_files']}. {note}",
                                  observed=observed, threshold=thr, dedup_scope=scope, evidence=[note])
        if cur["files"] < int(thr["min_files"]) and cur["bytes"] < float(thr["min_bytes"]):
            return self.clear("Download volume in this window below review thresholds.", observed=observed, threshold=thr)
        n_min = int(ctx.cfg("D16_MIN_WINDOWS"))
        sf = ctx.baselines.stats(f.entity_key, "download_window_files", ctx.ts, min_samples=n_min)
        sb = ctx.baselines.stats(f.entity_key, "download_window_bytes", ctx.ts, min_samples=n_min)
        if sf is None or sb is None:
            return self.not_evaluated(f"Insufficient download history (< {n_min} prior active windows).",
                                      observed=observed, threshold=thr)
        zf, zb = sf.robust_z(cur["files"], floor=1.0), sb.robust_z(cur["bytes"], floor=1024 * 1024.0)
        zt = float(ctx.cfg("ROBUST_Z_THRESHOLD")) * 2 / 3
        observed.update(files_robust_z=round(zf, 2), bytes_robust_z=round(zb, 2))
        base = {"files": sf.as_dict(), "bytes": sb.as_dict()}
        if max(zf, zb) < zt:
            return self.clear("Download window typical for this user.", observed=observed, baseline=base, threshold=thr)
        sev = "HIGH" if max(zf, zb) >= 2 * zt else "MEDIUM"
        return self.triggered(sev, f"{cur['files']} files / {mb(cur['bytes'])} MB downloaded in one window "
                                   f"(robust z files {zf:.1f}, bytes {zb:.1f}). {note}",
                              observed=observed, baseline=base, threshold={**thr, "robust_z": zt},
                              dedup_scope=scope, evidence=[note])

    def commit(self, ctx, result, flagged):
        if "d16" not in ctx.cache:
            return
        cur, closing = ctx.cache["d16"]
        if flagged:
            cur = {**cur, "tainted": True}
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, cur)
        if closing:
            trusted = not closing.get("tainted", False)
            key = f"window:{closing['bucket']}"
            ctx.baselines.add_sample(ctx.f.entity_key, "download_window_files", closing["files"], closing["bucket"], key, None, trusted)
            ctx.baselines.add_sample(ctx.f.entity_key, "download_window_bytes", closing["bytes"], closing["bucket"], key, None, trusted)
