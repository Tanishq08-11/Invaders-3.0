"""
Traffic-pattern detectors: D8 automated transfer, D21 unusual protocol tunnel,
D22 connection-failure anomalies, D28 internal lateral movement.
"""
from core.models import EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, ORG_ENTITY
from services.detection import enrichment
from services.detection.base import G_BEHAVIOUR, G_PROTOCOL, Detector
from services.detection.detectors.volume import mb

NET = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
TLS_PORTS = {443, 8443, 993, 995, 465, 853, 636, 989, 990, 5061, 6697, 8883}
DEFAULT_ADMIN_PORTS = [22, 135, 139, 445, 3389, 5900, 5985, 5986]


class AutomatedTransfer(Detector):
    """
    Uses the outbound side's fixed-bin histograms from the flow aggregator:
      • normalised Shannon entropy of the inter-arrival-time histogram (0 = all gaps in one
        bin, 1 = uniform over bins) — computed from the actual distribution;
      • coefficient of variation (std/mean) of inter-arrival times — reported as CV,
        not as entropy;
      • normalised entropy of the packet-size histogram.
    Regular, uniform timing is consistent with scripted transfers — and with backups or
    streaming, so this is evidence (LOW), not a verdict.
    """
    id, name, version, group = "D8", "Automated transfer", "1.0", G_PROTOCOL
    event_types = (EVENT_NETWORK_FLOW,)
    requires = ("completed flow", "outbound per-direction histograms", "≥D8_MIN_PACKETS outbound packets")

    def evaluate(self, ctx):
        f = ctx.f
        if not f.completed:
            return self.not_evaluated("Flow not complete.", missing=["completed_flow"])
        if f.org_direction not in ("outbound", "inbound"):
            return self.clear("No internal→external path.") if f.org_direction != "unknown" else \
                self.not_evaluated("Direction unknown.", missing=["org_direction"])
        side = f.outbound_side or {}
        iat_h, size_h = side.get("iat_histogram") or {}, side.get("size_histogram") or {}
        n = int(side.get("packets") or 0)
        need = int(ctx.cfg("D8_MIN_PACKETS"))
        if not iat_h or not size_h:
            return self.not_evaluated("Timing histograms unavailable for this flow.", missing=["iat_histogram"])
        if n < need:
            return self.not_evaluated(f"Too few outbound packets for timing analysis ({n} < {need}).",
                                      observed={"outbound_packets": n})
        iat = side.get("inter_arrival_s") or {}
        mean, std = iat.get("mean"), iat.get("std")
        cv = (std / mean) if mean else None
        observed = {"outbound_packets": n, "outbound_bytes": f.outbound_bytes,
                    "iat_entropy_normalized": iat_h.get("entropy_normalized"), "iat_entropy_bits": iat_h.get("entropy_bits"),
                    "iat_cv": round(cv, 4) if cv is not None else None,
                    "size_entropy_normalized": size_h.get("entropy_normalized"), "iat_histogram": iat_h.get("counts"),
                    "size_histogram": size_h.get("counts"), "entity_key": f.entity_key}
        thr = {"max_iat_entropy_normalized": ctx.cfg("D8_MAX_IAT_ENTROPY"), "max_iat_cv": ctx.cfg("D8_MAX_IAT_CV"),
               "min_outbound_bytes": ctx.cfg("D8_MIN_OUTBOUND_BYTES")}
        if (f.outbound_bytes or 0) < float(thr["min_outbound_bytes"]):
            return self.clear("Outbound volume too small to matter.", observed=observed, threshold=thr)
        h = iat_h.get("entropy_normalized")
        if h is None or cv is None:
            return self.not_evaluated("Inter-arrival statistics undefined.", observed=observed)
        if h <= float(thr["max_iat_entropy_normalized"]) and cv <= float(thr["max_iat_cv"]):
            return self.triggered("LOW", f"Machine-regular outbound timing: IAT entropy {h:.2f} (normalised), CV {cv:.2f} over "
                                         f"{n} packets, {mb(f.outbound_bytes)} MB. Also typical of backup/sync software.",
                                  observed=observed, threshold=thr, evidence_only=True)
        return self.clear("Outbound timing not machine-regular.", observed=observed, threshold=thr)


class ProtocolTunnel(Detector):
    id, name, version, group = "D21", "Unusual protocol tunnel", "1.0", G_PROTOCOL
    event_types = NET
    requires = ("responder port", "application-protocol hint (flows)", "per-entity port profile")
    STATE, ORG_STATE = "d21_ports", "d21_port_entities"

    def evaluate(self, ctx):
        f = ctx.f
        if f.org_direction not in ("outbound", "inbound"):
            return self.clear("No internal→external path.") if f.org_direction != "unknown" else \
                self.not_evaluated("Direction unknown.", missing=["org_direction"])
        if f.service_port is None or not f.protocol:
            return self.not_evaluated("No transport port/protocol.", missing=["service_port"])
        pk = f"{f.protocol}/{f.service_port}"
        ctx.cache["d21"] = pk
        findings = []
        payload = f.event_type == EVENT_NETWORK_FLOW and ((f.outbound_side or {}).get("payload_packets") or 0) > 0
        app = f.app_protocol
        if f.event_type == EVENT_NETWORK_FLOW:
            if f.service_port == 53 and payload and app not in ("dns", None):
                findings.append(("MEDIUM", f"non-DNS payload ({app}) on port 53"))
            if f.service_port == 53 and payload and app is None and f.protocol == "UDP" and (f.outbound_bytes or 0) > 64 * 1024:
                findings.append(("LOW", "large unparsed UDP/53 volume"))
            if app == "ssh" and f.service_port in (80, 443, 8080, 8443):
                findings.append(("MEDIUM", f"SSH protocol on web port {f.service_port}"))
            if app == "tls" and f.service_port not in TLS_PORTS:
                findings.append(("LOW", f"TLS on non-standard port {f.service_port}"))
            if f.service_port == 443 and f.protocol == "TCP" and payload and app in ("http", "unknown", "ssh"):
                findings.append(("LOW", f"port 443 carrying {app} rather than TLS"))
        st = ctx.baselines.get_state(f.entity_key, self.STATE) if f.entity_key else {}
        org = ctx.baselines.get_state(ORG_ENTITY, self.ORG_STATE)
        flows = int(st.get("flows", 0))
        used_by = len((org.get("ports") or {}).get(pk, []))
        observed = {"protocol_port": pk, "app_protocol": app, "entity_flows": flows, "entities_using_port": used_by,
                    "destination": f.destination, "entity_key": f.entity_key}
        novelty_evaluated = f.entity_key is not None and flows >= int(ctx.cfg("D21_MIN_ENTITY_FLOWS"))
        if novelty_evaluated and pk not in (st.get("ports") or {}) and used_by < int(ctx.cfg("D21_COMMON_MIN_ENTITIES")):
            findings.append(("LOW", f"{pk} never used by this entity and by {used_by} entities organisation-wide "
                                    "(unrecognised combination, not confirmed tunnelling)"))
        avail = {} if novelty_evaluated else {"partial": True, "novelty": "insufficient entity port history"}
        if not findings:
            return self.clear("Protocol/port combination consistent with observed behaviour.", observed=observed,
                              availability=avail)
        sev = "MEDIUM" if any(s == "MEDIUM" for s, _ in findings) else "LOW"
        return self.triggered(sev, "Protocol/port anomaly: " + "; ".join(t for _, t in findings) + ".",
                              observed={**observed, "findings": [t for _, t in findings]}, availability=avail,
                              evidence_only=sev == "LOW")

    def commit(self, ctx, result, flagged):
        pk = ctx.cache.get("d21")
        ent = ctx.f.entity_key
        if not pk or not ent or flagged:
            return
        st = ctx.baselines.get_state(ent, self.STATE)
        ports = st.setdefault("ports", {})
        first_use = pk not in ports
        ports[pk] = ports.get(pk, 0) + 1
        if len(ports) > 300:
            st["ports"] = dict(sorted(ports.items(), key=lambda kv: -kv[1])[:300])
        st["flows"] = int(st.get("flows", 0)) + 1
        ctx.baselines.set_state(ent, self.STATE, st)
        if first_use:
            org = ctx.baselines.get_state(ORG_ENTITY, self.ORG_STATE)
            lst = org.setdefault("ports", {}).setdefault(pk, [])
            if ent not in lst and len(lst) < 50:
                lst.append(ent)
                ctx.baselines.set_state(ORG_ENTITY, self.ORG_STATE, org)


class ConnectionFailures(Detector):
    id, name, version, group = "D22", "Connection failure anomalies", "1.0", G_BEHAVIOUR
    event_types = (EVENT_NETWORK_FLOW,)
    requires = ("TCP handshake outcome (flows with SYN observed)", "per-entity failure-window baseline")
    STATE = "d22_window"

    def evaluate(self, ctx):
        f = ctx.f
        if f.protocol != "TCP":
            return self.not_evaluated("Connection outcome not observable for non-TCP traffic.", missing=["tcp"])
        if f.tcp_outcome in (None, "partial", "established_midstream"):
            return self.not_evaluated("Handshake not observed for this flow.", missing=["tcp_handshake"])
        if not f.initiator_internal or not f.entity_key:
            return self.clear("Not a connection attempt by an internal entity.")
        W = int(ctx.cfg("D22_WINDOW_S"))
        bucket = int(ctx.ts // W * W)
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        failed = f.tcp_outcome in ("no_response", "rejected")
        if st.get("bucket") == bucket:
            cur = {**st, "targets": list(st.get("targets", []))}
            closing = None
        else:
            closing = st if st.get("bucket") is not None and st["bucket"] < bucket else None
            cur = {"bucket": bucket, "failures": 0, "attempts": 0, "targets": []}
        cur["attempts"] += 1
        if failed:
            cur["failures"] += 1
            tgt = f"{f.responder_ip}:{f.service_port}"
            if tgt not in cur["targets"] and len(cur["targets"]) < 500:
                cur["targets"].append(tgt)
        ctx.cache["d22"] = (cur, closing)
        observed = {"window_start": bucket, "failures": cur["failures"], "attempts": cur["attempts"],
                    "distinct_failed_targets": len(cur["targets"]), "tcp_outcome": f.tcp_outcome, "entity_key": f.entity_key}
        if not failed:
            return self.clear("Connection established.", observed=observed)
        thr = {"min_failures": ctx.cfg("D22_MIN_FAILURES"), "scan_distinct_targets": ctx.cfg("D22_SCAN_DISTINCT_TARGETS")}
        scope = f"D22:{f.entity_key}:{bucket}"
        if len(cur["targets"]) >= int(thr["scan_distinct_targets"]):
            return self.triggered("HIGH", f"{cur['failures']} failed connections to {len(cur['targets'])} distinct targets "
                                          f"within {W // 60} min — scan-like pattern.", observed=observed, threshold=thr,
                                  dedup_scope=scope)
        if cur["failures"] < int(thr["min_failures"]):
            return self.clear("Failures in this window below the review threshold.", observed=observed, threshold=thr)
        stt = ctx.baselines.stats(f.entity_key, "failure_window_count", ctx.ts, min_samples=10)
        if stt is None:
            return self.not_evaluated("Insufficient failure-window history.", observed=observed, threshold=thr)
        z = stt.robust_z(cur["failures"], floor=2.0)
        if z < float(ctx.cfg("ROBUST_Z_THRESHOLD")):
            return self.clear("Failure count typical for this entity.", observed={**observed, "robust_z": round(z, 2)},
                              baseline=stt.as_dict(), threshold=thr)
        return self.triggered("MEDIUM", f"{cur['failures']} failed connections in {W // 60} min (robust z {z:.1f}).",
                              observed={**observed, "robust_z": round(z, 2)}, baseline=stt.as_dict(), threshold=thr,
                              dedup_scope=scope)

    def commit(self, ctx, result, flagged):
        if "d22" not in ctx.cache:
            return
        cur, closing = ctx.cache["d22"]
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, {**cur, "tainted": cur.get("tainted") or flagged})
        if closing and closing.get("failures", 0) > 0:
            ctx.baselines.add_sample(ctx.f.entity_key, "failure_window_count", closing["failures"], closing["bucket"],
                                     f"window:{closing['bucket']}", None, trusted=not closing.get("tainted", False))


class LateralMovement(Detector):
    id, name, version, group = "D28", "Internal lateral movement", "1.0", G_BEHAVIOUR
    event_types = NET
    requires = ("internal↔internal flows", "admin-port policy", "per-entity internal peer history")
    STATE, WIN = "d28_peers", "d28_window"

    def evaluate(self, ctx):
        f = ctx.f
        if f.org_direction == "unknown":
            return self.not_evaluated("Direction unknown.", missing=["org_direction"])
        if f.org_direction != "internal":
            return self.clear("Not internal traffic — lateral movement is only assessed on internal observations.")
        if not f.entity_key or not f.initiator_internal:
            return self.not_evaluated("Initiating internal entity unknown.", missing=["entity"])
        admin_ports = enrichment.policy.get("admin_ports") or DEFAULT_ADMIN_PORTS
        if f.service_port not in admin_ports:
            ctx.cache["d28"] = ("other", None)
            return self.clear("Not an administrative protocol port.")
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        peer = f"{f.responder_ip}:{f.service_port}"
        ctx.cache["d28"] = ("admin", peer)
        flows = int(st.get("flows", 0))
        observed = {"peer": peer, "entity_history_flows": flows, "entity_key": f.entity_key}
        if flows < int(ctx.cfg("D28_MIN_HISTORY_FLOWS")):
            return self.not_evaluated(f"Insufficient internal history ({flows} flows).", observed=observed)
        if peer in (st.get("peers") or []):
            return self.clear("Known administrative relationship.", observed=observed)
        W = int(ctx.cfg("D28_WINDOW_S"))
        bucket = int(ctx.ts // W * W)
        win = ctx.baselines.get_state(f.entity_key, self.WIN)
        new_peers = list(win.get("new_peers", [])) if win.get("bucket") == bucket else []
        if peer not in new_peers:
            new_peers.append(peer)
        ctx.cache["d28_win"] = {"bucket": bucket, "new_peers": new_peers[:200]}
        observed.update(new_admin_peers_in_window=len(new_peers), window_s=W)
        thr = {"min_new_hosts": ctx.cfg("D28_MIN_NEW_HOSTS")}
        if len({p.split(':')[0] for p in new_peers}) >= int(thr["min_new_hosts"]):
            return self.triggered("HIGH", f"{f.entity_key} opened administrative connections to {len(new_peers)} internal "
                                          f"hosts it never used before within {W // 60} min.",
                                  observed={**observed, "new_peers": new_peers[:20]}, threshold=thr,
                                  dedup_scope=f"D28:{f.entity_key}:{bucket}")
        return self.clear("New administrative peer, below the fan-out threshold.", observed=observed, threshold=thr)

    def commit(self, ctx, result, flagged):
        val = ctx.cache.get("d28")
        ent = ctx.f.entity_key
        if not val or not ent:
            return
        if "d28_win" in ctx.cache:
            ctx.baselines.set_state(ent, self.WIN, ctx.cache["d28_win"])
        if flagged:
            return
        st = ctx.baselines.get_state(ent, self.STATE)
        st["flows"] = int(st.get("flows", 0)) + 1
        kind, peer = val
        if kind == "admin" and peer not in st.setdefault("peers", []) and len(st["peers"]) < 500:
            st["peers"].append(peer)
        ctx.baselines.set_state(ent, self.STATE, st)
