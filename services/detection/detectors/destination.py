"""
Destination detectors: D2 unknown destination, D3 unusual country/ASN, D18 leak via
trusted sites, D19 beaconing, D20 remote desktop out, D23 egress policy violations.
The destination is the observed TLS SNI when present, otherwise the external IP —
hostnames are never inferred from addresses.
"""
import statistics

from core.models import EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, ORG_ENTITY
from services.detection import enrichment
from services.detection.base import G_DESTINATION, G_EXFIL, Detector
from services.detection.detectors.volume import TRANSFER_MIN_BYTES, mb

NET = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)


def external_prereq(det, f):
    if f.org_direction == "unknown":
        return det.not_evaluated("Organisation direction unknown.", missing=["org_direction"])
    if not f.external_ip:
        return det.clear(f"No external endpoint ({f.org_direction} traffic).")
    return None


class UnknownDestination(Detector):
    id, name, version, group = "D2", "Unknown destination", "1.0", G_DESTINATION
    event_types = NET
    requires = ("external destination (SNI or IP)", f"organisation destination history ≥ D2_MIN_ORG_FLOWS flows")

    def evaluate(self, ctx):
        f = ctx.f
        gate = external_prereq(self, f)
        if gate:
            return gate
        dest = f.destination
        org_total = ctx.baselines.org_flow_total()
        observed = {"destination": dest, "destination_kind": f.destination_kind, "outbound_bytes": f.outbound_bytes,
                    "entity_key": f.entity_key}
        if org_total < int(ctx.cfg("D2_MIN_ORG_FLOWS")):
            return self.not_evaluated(f"Destination history warming up ({org_total}/{ctx.cfg('D2_MIN_ORG_FLOWS')} flows).",
                                      observed=observed, baseline={"org_flows": org_total})
        org = ctx.baselines.destination(ORG_ENTITY, dest)
        ent = ctx.baselines.destination(f.entity_key, dest) if f.entity_key else None
        popularity = ctx.baselines.destination_popularity(dest)
        observed.update(first_seen_org=org is None, first_seen_entity=ent is None, entities_using=popularity,
                        org_flow_count=org.flow_count if org else 0)
        base = {"org_flows": org_total}
        out = f.outbound_bytes or 0
        if org is None and out >= float(ctx.cfg("D2_MIN_OUTBOUND_BYTES")):
            sev = "MEDIUM" if out >= float(ctx.cfg("D1_MIN_OUTBOUND_BYTES")) else "LOW"
            return self.triggered(sev, f"First time anyone in the organisation sent data to {dest} ({mb(out)} MB). "
                                       "A new destination is evidence for review, not proof of a threat.",
                                  score=30.0 if sev == "MEDIUM" else 15.0, evidence_only=sev == "LOW",
                                  observed=observed, baseline=base,
                                  threshold={"min_outbound_bytes": ctx.cfg("D2_MIN_OUTBOUND_BYTES")})
        if org is None:
            return self.clear("First-seen destination with negligible outbound volume.", observed=observed, baseline=base)
        return self.clear(f"Destination seen before ({org.flow_count} flows, {popularity} entities).",
                          observed=observed, baseline=base)

    def commit(self, ctx, result, flagged):
        f = ctx.f
        if f.external_ip and f.destination:
            ctx.baselines.touch_destination(f.entity_key, f.destination, f.destination_kind, ctx.ts, f.outbound_bytes or 0)


class UnusualCountry(Detector):
    id, name, version, group = "D3", "Unusual country/host", "1.0", G_DESTINATION
    event_types = NET
    requires = ("GeoIP country/ASN database (optional, local .mmdb)", "per-entity country history")
    STATE = "d3_geo"

    def dependencies(self):
        return {"geoip": enrichment.geoip.status()}

    def evaluate(self, ctx):
        f = ctx.f
        gate = external_prereq(self, f)
        if gate:
            return gate
        if not enrichment.geoip.available:
            return self.not_evaluated("GeoIP/ASN data unavailable: " + str(enrichment.geoip.status().get("reason")),
                                      missing=["geoip"], availability={"geoip": False})
        geo = enrichment.geoip.lookup(f.external_ip)
        if not geo or geo.get("scope") != "public":
            return self.clear("Destination is not a public address.", observed={"external_ip": f.external_ip})
        cc, asn = geo.get("country"), geo.get("asn")
        observed = {"external_ip": f.external_ip, "country": cc, "asn": asn, "as_org": geo.get("as_org"),
                    "entity_key": f.entity_key}
        ctx.cache["d3"] = (cc, asn)
        if not f.entity_key:
            return self.not_evaluated("No entity to compare against.", missing=["entity"], observed=observed)
        if cc is None and asn is None:
            return self.not_evaluated("Country and ASN unknown for this address — unknown is not treated as malicious.",
                                      observed=observed)
        st = ctx.baselines.get_state(f.entity_key, self.STATE)
        org = ctx.baselines.get_state(ORG_ENTITY, self.STATE)
        total = int(st.get("total", 0))
        if total < int(ctx.cfg("BASELINE_MIN_SAMPLES")):
            return self.not_evaluated(f"Insufficient destination-country history ({total} flows).", observed=observed,
                                      baseline={"flows": total})
        new_cc = cc is not None and cc not in st.get("countries", {})
        org_cc_entities = len((org.get("country_entities") or {}).get(cc or "", []))
        new_asn = asn is not None and str(asn) not in st.get("asns", {})
        base = {"flows": total, "countries": st.get("countries", {}), "org_entities_for_country": org_cc_entities}
        out = f.outbound_bytes or 0
        if new_cc and org_cc_entities < 3:
            sev = "MEDIUM" if out >= float(ctx.cfg("D2_MIN_OUTBOUND_BYTES")) else "LOW"
            return self.triggered(sev, f"First traffic from this entity to country {cc} (rare organisation-wide: "
                                       f"{org_cc_entities} entities); {mb(out)} MB outbound.",
                                  observed=observed, baseline=base, evidence_only=sev == "LOW")
        if new_asn:
            return self.triggered("LOW", f"First traffic from this entity to AS{asn} ({geo.get('as_org') or 'unknown org'}).",
                                  observed=observed, baseline=base, evidence_only=True)
        return self.clear("Country and ASN previously seen for this entity.", observed=observed, baseline=base)

    def commit(self, ctx, result, flagged):
        if "d3" not in ctx.cache or not ctx.f.entity_key or flagged:
            return
        cc, asn = ctx.cache["d3"]
        st = ctx.baselines.get_state(ctx.f.entity_key, self.STATE)
        st["total"] = int(st.get("total", 0)) + 1
        if cc:
            st.setdefault("countries", {})[cc] = st.get("countries", {}).get(cc, 0) + 1
        if asn is not None:
            st.setdefault("asns", {})[str(asn)] = st.get("asns", {}).get(str(asn), 0) + 1
        if len(st.get("asns", {})) > 500:
            st["asns"] = dict(sorted(st["asns"].items(), key=lambda kv: -kv[1])[:500])
        ctx.baselines.set_state(ctx.f.entity_key, self.STATE, st)
        if cc:
            org = ctx.baselines.get_state(ORG_ENTITY, self.STATE)
            ents = org.setdefault("country_entities", {}).setdefault(cc, [])
            if ctx.f.entity_key not in ents and len(ents) < 50:
                ents.append(ctx.f.entity_key)
            ctx.baselines.set_state(ORG_ENTITY, self.STATE, org)


class TrustedSiteLeak(Detector):
    id, name, version, group = "D18", "Leak via trusted sites", "1.0", G_EXFIL
    event_types = NET
    requires = ("observed TLS SNI", "destination policy (trusted categories)", "per-entity per-category volume baseline")

    def evaluate(self, ctx):
        f = ctx.f
        gate = external_prereq(self, f)
        if gate:
            return gate
        if not enrichment.policy.loaded:
            return self.not_evaluated("Destination policy not loaded.", missing=["policy"])
        if not f.sni:
            return self.not_evaluated("Destination hostname not observed (no SNI) — not inferred from the IP.",
                                      missing=["sni"])
        cat = enrichment.policy.trusted_category(f.sni)
        if not cat:
            return self.clear("Destination is not an approved cloud/collaboration service.", observed={"sni": f.sni})
        if f.outbound_bytes is None or not f.completed:
            return self.not_evaluated("Missing outbound bytes / incomplete flow.", missing=["outbound_bytes"])
        metric = f"trusted_out:{cat['category']}"
        x = f.outbound_bytes
        observed = {"sni": f.sni, "category": cat["category"], "policy_match": cat["matched"], "outbound_bytes": x,
                    "entity_key": f.entity_key}
        ctx.cache["d18"] = metric
        if x < float(ctx.cfg("D1_MIN_OUTBOUND_BYTES")):
            return self.clear("Outbound volume to the trusted service below the review floor.", observed=observed)
        st = ctx.baselines.stats(f.entity_key, metric, ctx.ts) if f.entity_key else None
        if st is None:
            return self.not_evaluated(f"Insufficient history of uploads to {cat['category']} for this entity.",
                                      observed=observed)
        z = st.robust_z(x, floor=float(TRANSFER_MIN_BYTES))
        zt = float(ctx.cfg("ROBUST_Z_THRESHOLD"))
        observed["robust_z"] = round(z, 2)
        if z < zt:
            return self.clear("Upload size typical for this entity and service category.", observed=observed,
                              baseline=st.as_dict(), threshold={"robust_z": zt})
        sev = "HIGH" if x >= float(ctx.cfg("D1_HIGH_OUTBOUND_BYTES")) else "MEDIUM"
        return self.triggered(sev, f"{mb(x)} MB uploaded to approved service {f.sni} ({cat['category']}), robust z {z:.1f} "
                                   "vs this entity's uploads to that category. Approved services are not assumed safe.",
                              observed=observed, baseline=st.as_dict(), threshold={"robust_z": zt})

    def commit(self, ctx, result, flagged):
        metric = ctx.cache.get("d18")
        f = ctx.f
        if metric and f.entity_key and (f.outbound_bytes or 0) >= TRANSFER_MIN_BYTES:
            ctx.baselines.add_sample(f.entity_key, metric, f.outbound_bytes, ctx.ts, ctx.sample_key, ctx.event.id,
                                     trusted=not flagged)


class Beaconing(Detector):
    """Regular connection starts to one destination: median interval and relative MAD of
    the gaps between successive *flow start* times (not per-packet inter-arrival)."""
    id, name, version, group = "D19", "Malware beaconing", "1.0", G_DESTINATION
    event_types = NET
    requires = ("flow start timestamps per entity+destination", "≥D19_MIN_INTERVALS intervals")
    MAX_STARTS = 40

    def evaluate(self, ctx):
        f = ctx.f
        gate = external_prereq(self, f)
        if gate:
            return gate
        if not f.initiator_internal:
            return self.clear("Connection not initiated by the internal endpoint.")
        if not f.entity_key or f.ts is None:
            return self.not_evaluated("No entity or start time.", missing=["entity", "timestamp"])
        key = f"d19:{f.destination}:{f.service_port}"
        st = ctx.baselines.get_state(f.entity_key, key)
        starts = list(st.get("starts", []))
        if starts and abs(f.ts - starts[-1]) < 1.0:
            ctx.cache["d19"] = None
            return self.clear("Duplicate connection start (within 1 s) ignored.")
        starts = sorted(starts + [f.ts])[-self.MAX_STARTS:]
        ctx.cache["d19"] = (key, starts)
        gaps = [b - a for a, b in zip(starts, starts[1:]) if b - a > 0]
        observed = {"destination": f.destination, "service_port": f.service_port, "samples": len(gaps), "entity_key": f.entity_key}
        need = int(ctx.cfg("D19_MIN_INTERVALS"))
        if len(gaps) < need:
            return self.not_evaluated(f"{len(gaps)}/{need} connection intervals observed for this destination.",
                                      observed=observed)
        recent = gaps[-need * 2:]
        med = statistics.median(recent)
        mad = statistics.median([abs(g - med) for g in recent])
        rel = mad / med if med > 0 else None
        observed.update(median_interval_s=round(med, 2), mad_s=round(mad, 3), relative_dispersion=round(rel, 4) if rel is not None else None,
                        min_interval_s=round(min(recent), 2), max_interval_s=round(max(recent), 2))
        thr = {"max_relative_dispersion": ctx.cfg("D19_MAX_REL_DISPERSION"),
               "interval_range_s": [ctx.cfg("D19_MIN_INTERVAL_S"), ctx.cfg("D19_MAX_INTERVAL_S")], "min_intervals": need}
        regular = rel is not None and rel <= float(thr["max_relative_dispersion"])
        in_range = float(thr["interval_range_s"][0]) <= med <= float(thr["interval_range_s"][1])
        if regular and in_range:
            day = int(f.ts // 86400)
            return self.triggered("MEDIUM", f"{len(recent)} connections to {f.destination}:{f.service_port} every "
                                            f"{med:.1f} s (±{mad:.2f} s, dispersion {rel:.3f}). Periodic software updates "
                                            "and health checks can also do this.",
                                  observed=observed, threshold=thr, dedup_scope=f"D19:{f.entity_key}:{key}:{day}")
        return self.clear("Connection timing not regular enough for beaconing.", observed=observed, threshold=thr)

    def commit(self, ctx, result, flagged):
        val = ctx.cache.get("d19")
        if val and ctx.f.entity_key:
            key, starts = val
            ctx.baselines.set_state(ctx.f.entity_key, key, {"starts": starts})


class RemoteDesktopOut(Detector):
    id, name, version, group = "D20", "Remote desktop out", "1.0", G_DESTINATION
    event_types = NET
    requires = ("responder port", "organisation direction", "rdp_approved_destinations policy")
    RDP_PORT = 3389

    def evaluate(self, ctx):
        f = ctx.f
        if f.service_port != self.RDP_PORT:
            return self.clear("Not TCP/UDP 3389.")
        if f.org_direction == "unknown":
            return self.not_evaluated("Direction unknown.", missing=["org_direction"])
        observed = {"protocol": f.protocol, "service_port": f.service_port, "org_direction": f.org_direction,
                    "responder": f.responder_ip, "outbound_bytes": f.outbound_bytes, "entity_key": f.entity_key}
        if f.org_direction == "internal":
            return self.clear("Internal RDP (assessed by D28 lateral movement, not as egress).", observed=observed)
        if f.org_direction == "inbound":
            return self.clear("Inbound RDP to an internal host — not outbound remote desktop.", observed=observed)
        if f.org_direction == "external":
            return self.clear("Neither endpoint is internal.", observed=observed)
        approved = enrichment.policy.matches_list("rdp_approved_destinations", f.sni, f.external_ip)
        if approved:
            return self.clear(f"Approved RDP destination ({approved}).", observed={**observed, "approved_match": approved})
        sev = "HIGH" if (f.outbound_bytes or 0) >= float(ctx.cfg("D1_MIN_OUTBOUND_BYTES")) else "MEDIUM"
        return self.triggered(sev, f"Outbound {f.protocol}/3389 (RDP's registered port) from {f.internal_ip} to external "
                                   f"{f.external_ip}, not on the approved list. The port alone does not prove RDP.",
                              observed=observed, threshold={"approved_destinations": enrichment.policy.get("rdp_approved_destinations") or []})


class EgressPolicy(Detector):
    id, name, version, group = "D23", "Egress policy violation", "1.0", G_EXFIL
    event_types = NET
    requires = ("destination policy egress_rules",)

    def evaluate(self, ctx):
        f = ctx.f
        if not enrichment.policy.loaded:
            return self.not_evaluated("Destination policy not loaded.", missing=["policy"])
        rules = enrichment.policy.get("egress_rules") or []
        if not rules:
            return self.not_evaluated("No egress rules configured.", missing=["egress_rules"])
        if f.org_direction == "unknown":
            return self.not_evaluated("Direction unknown.", missing=["org_direction"])
        hits = []
        for rule in rules:
            if rule.get("direction", "outbound") != f.org_direction:
                continue
            reasons = []
            if rule.get("ports") and f.service_port in rule["ports"] and \
                    (not rule.get("protocols") or (f.protocol or "").upper() in rule["protocols"]):
                reasons.append(f"{f.protocol}/{f.service_port}")
            dm = enrichment.policy.domain_matches(f.sni, rule.get("domains"))
            if dm:
                reasons.append(f"domain {dm}")
            am = enrichment.policy.address_matches(f.external_ip, rule.get("cidrs"))
            if am:
                reasons.append(f"address {am}")
            if reasons:
                hits.append({"rule_id": rule.get("id"), "description": rule.get("description"),
                             "severity": rule.get("severity", "MEDIUM"), "matched": reasons})
        observed = {"org_direction": f.org_direction, "service_port": f.service_port, "protocol": f.protocol,
                    "destination": f.destination, "entity_key": f.entity_key}
        if not hits:
            return self.clear("No egress rule matched.", observed=observed)
        sev = max((h["severity"] for h in hits), key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s))
        return self.triggered(sev, "Egress policy: " + "; ".join(f"{h['rule_id']} ({', '.join(h['matched'])})" for h in hits),
                              observed={**observed, "rules": hits},
                              threshold={"policy_version": enrichment.policy.get("version")})
