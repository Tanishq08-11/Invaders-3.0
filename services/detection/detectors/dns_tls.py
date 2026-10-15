"""
D17 DNS tunnelling (cleartext DNS only), D12 hidden tunnel / personal VPN / Tor,
D26 TLS fingerprint changes.

DNS: query names come from cleartext DNS on port 53. DNS over HTTPS / TLS is encrypted;
those queries are not observable and are reported as not evaluated, never as clear.
The registered domain is approximated as the last two labels (three for common
second-level suffixes such as co.uk); no public-suffix list is bundled.
"""
import math
from collections import Counter

from core.models import EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD, ORG_ENTITY
from services.detection import enrichment
from services.detection.base import G_DESTINATION, G_PROTOCOL, Detector

NET = (EVENT_NETWORK_FLOW, EVENT_NETWORK_RECORD)
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}
VPN_PORTS = {("UDP", 1194): "OpenVPN", ("TCP", 1194): "OpenVPN", ("UDP", 51820): "WireGuard",
             ("UDP", 500): "IPsec IKE", ("UDP", 4500): "IPsec NAT-T", ("TCP", 1723): "PPTP",
             ("TCP", 9001): "Tor ORPort (common)", ("TCP", 9030): "Tor DirPort (common)"}


def label_entropy(s: str) -> float:
    """Shannon entropy in bits per character of a label's character distribution."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def split_domain(name: str):
    labels = [l for l in name.lower().rstrip(".").split(".") if l]
    if len(labels) < 2:
        return name, ""
    k = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-k:]), ".".join(labels[:-k])


class DnsTunnel(Detector):
    id, name, version, group = "D17", "DNS tunnelling", "1.0", G_PROTOCOL
    event_types = NET
    requires = ("cleartext DNS query metadata (port 53)",)
    MAX_SUBS = 300

    def evaluate(self, ctx):
        f = ctx.f
        if f.service_port == 853 or (f.sni and f.sni.startswith(("dns.", "doh.")) and f.service_port == 443):
            return self.not_evaluated("Encrypted DNS (DoT/DoH): query names are not observable.", missing=["dns_queries"])
        if f.service_port != 53 and not f.dns:
            return self.clear("Not DNS traffic.")
        if not f.dns or not f.dns.get("names"):
            return self.not_evaluated("No parseable DNS query metadata for this flow.", missing=["dns_queries"])
        if not f.entity_key:
            return self.not_evaluated("No entity to aggregate queries for.", missing=["entity"])
        W = int(ctx.cfg("D17_WINDOW_S"))
        bucket = int(ctx.ts // W * W)
        updates, findings = {}, []
        for name in f.dns["names"]:
            base, sub = split_domain(name)
            if not sub:
                continue
            longest = max((len(l) for l in sub.split(".")), default=0)
            ent = label_entropy(sub.replace(".", ""))
            key = f"d17:{base}"
            st = updates.get(key) or ctx.baselines.get_state(f.entity_key, key)
            if st.get("bucket") != bucket:
                st = {"bucket": bucket, "subs": [], "queries": 0, "nx": 0, "len_sum": 0.0, "ent_sum": 0.0}
            st = {**st, "subs": list(st["subs"])}
            if sub not in st["subs"] and len(st["subs"]) < self.MAX_SUBS:
                st["subs"].append(sub)
                st["len_sum"] += longest
                st["ent_sum"] += ent
            st["queries"] += 1
            updates[key] = st
            if longest >= 52 and ent >= 4.0:
                findings.append(("LOW", base, f"single query with a {longest}-char, {ent:.2f}-bit/char label under {base}"))
        nx = int(f.dns.get("nxdomain") or 0)
        for key, st in updates.items():
            if nx:
                st["nx"] += nx
            n = len(st["subs"])
            if n >= int(ctx.cfg("D17_MIN_SUBDOMAINS")):
                mean_len, mean_ent = st["len_sum"] / n, st["ent_sum"] / n
                if mean_len >= float(ctx.cfg("D17_MIN_LABEL_LEN")) or mean_ent >= float(ctx.cfg("D17_MIN_LABEL_ENTROPY")):
                    findings.append(("HIGH", key[4:], f"{n} distinct subdomains of {key[4:]} in {W // 60} min "
                                                      f"(mean longest label {mean_len:.1f} chars, mean entropy {mean_ent:.2f} bit/char, "
                                                      f"NXDOMAIN {st['nx']}/{st['queries']})"))
        ctx.cache["d17"] = updates
        observed = {"query_names": f.dns["names"], "qtypes": f.dns.get("qtypes"), "nxdomain": nx, "entity_key": f.entity_key,
                    "window": {k[4:]: {"distinct_subdomains": len(v["subs"]), "queries": v["queries"]} for k, v in updates.items()}}
        thr = {"window_s": W, "min_subdomains": ctx.cfg("D17_MIN_SUBDOMAINS"), "min_mean_label_len": ctx.cfg("D17_MIN_LABEL_LEN"),
               "min_mean_label_entropy": ctx.cfg("D17_MIN_LABEL_ENTROPY")}
        if not findings:
            return self.clear("Query names consistent with ordinary DNS use.", observed=observed, threshold=thr)
        sev = "HIGH" if any(s == "HIGH" for s, _, _ in findings) else "LOW"
        bases = sorted({b for _, b, _ in findings})
        return self.triggered(sev, "DNS tunnelling indicators: " + "; ".join(t for _, _, t in findings) + ".",
                              observed={**observed, "findings": [t for _, _, t in findings]}, threshold=thr,
                              evidence_only=sev == "LOW", dedup_scope=f"D17:{f.entity_key}:{','.join(bases)}:{bucket}")

    def commit(self, ctx, result, flagged):
        for key, st in (ctx.cache.get("d17") or {}).items():
            ctx.baselines.set_state(ctx.f.entity_key, key, st)


class HiddenTunnel(Detector):
    id, name, version, group = "D12", "Hidden tunnel / personal VPN / Tor", "1.0", G_DESTINATION
    event_types = NET
    requires = ("threat-intel files (optional, THREAT_INTEL_DIR)", "TLS JA3 (optional)", "responder port")

    def dependencies(self):
        return {"threat_intel": enrichment.intel.status()}

    def evaluate(self, ctx):
        f = ctx.f
        if f.org_direction not in ("outbound", "inbound"):
            return self.clear("No internal→external path.") if f.org_direction != "unknown" else \
                self.not_evaluated("Direction unknown.", missing=["org_direction"])
        findings = []
        intel_ok = enrichment.intel.available
        if intel_ok:
            for m in enrichment.intel.match_ip(f.external_ip):
                sev = "HIGH" if "tor" in m["category"] else "MEDIUM"
                findings.append((sev, f"{f.external_ip} listed as {m['category']} by {m['source']} (updated {m['updated']}"
                                      f"{', STALE' if m['stale'] else ''})", m))
            for m in enrichment.intel.match_domain(f.sni):
                findings.append(("MEDIUM", f"SNI {f.sni} listed as {m['category']} by {m['source']}", m))
            for m in enrichment.intel.match_ja3(f.tls.get("ja3")):
                findings.append(("MEDIUM", f"JA3 {f.tls.get('ja3')} listed as {m['category']} by {m['source']}", m))
        vpn = VPN_PORTS.get(((f.protocol or "").upper(), f.service_port))
        long_lived = (f.duration or 0) >= 120 and (f.outbound_bytes or 0) > 0 and (f.inbound_bytes or 0) > 0
        if vpn and long_lived:
            findings.append(("LOW", f"long-lived bidirectional {f.protocol}/{f.service_port} session (port commonly used by "
                                    f"{vpn}) — a port is not proof of a tunnel", None))
        ja4 = f.tls.get("zeek_ja4")
        observed = {"external_ip": f.external_ip, "sni": f.sni, "ja3": f.tls.get("ja3"),
                    "ja4": ja4, "ja4_provenance": "zeek" if ja4 else None,
                    "service_port": f.service_port, "duration_s": f.duration, "entity_key": f.entity_key}
        avail = {} if intel_ok else {"partial": True, "threat_intel": "no threat-intelligence sources loaded"}
        if not findings:
            if not intel_ok:
                return self.clear("No VPN-port heuristic matched; threat-intel matching unavailable.", observed=observed,
                                  availability=avail)
            return self.clear("No intel match and no VPN-port heuristic matched.", observed=observed)
        sev = max((s for s, _, _ in findings), key=lambda s: ["LOW", "MEDIUM", "HIGH"].index(s))
        return self.triggered(sev, "; ".join(t for _, t, _ in findings) + ".",
                              observed={**observed, "intel_matches": [m for _, _, m in findings if m]},
                              availability=avail, evidence_only=sev == "LOW")


class TlsFingerprintChange(Detector):
    id, name, version, group = "D26", "TLS fingerprint change", "1.0", G_PROTOCOL
    event_types = (EVENT_NETWORK_FLOW,)
    requires = ("complete ClientHello (JA3)", "≥D26_MIN_OBSERVATIONS prior fingerprints per entity+destination")
    ORG = "d26_org_ja3"

    def evaluate(self, ctx):
        f = ctx.f
        ja3 = f.tls.get("ja3")
        if not ja3:
            return self.not_evaluated("No complete ClientHello / JA3 observed for this flow.", missing=["ja3"])
        if not f.entity_key or not f.destination:
            return self.not_evaluated("No entity / destination.", missing=["entity"])
        key = f"d26:{f.destination}"
        st = ctx.baselines.get_state(f.entity_key, key)
        org = ctx.baselines.get_state(ORG_ENTITY, self.ORG)
        seen = st.get("seen", {})
        total = sum(seen.values())
        ctx.cache["d26"] = (key, ja3)
        ja4 = f.tls.get("zeek_ja4")
        observed = {"ja3": ja3, "destination": f.destination, "known_fingerprints": list(seen)[:10], "observations": total,
                    "ja4": ja4, "ja4_provenance": "zeek" if ja4 else None, "entity_key": f.entity_key}
        if total < int(ctx.cfg("D26_MIN_OBSERVATIONS")):
            return self.not_evaluated(f"{total} prior fingerprints for this destination (need {ctx.cfg('D26_MIN_OBSERVATIONS')}).",
                                      observed=observed)
        if ja3 in seen:
            return self.clear("Known client fingerprint for this destination.", observed=observed)
        org_known = ja3 in (org.get("ja3") or [])
        sev = "LOW" if org_known else "MEDIUM"
        return self.triggered(sev, f"New TLS client fingerprint {ja3} toward {f.destination} after {total} observations of "
                                   f"{len(seen)} other fingerprint(s)" + ("" if org_known else "; never seen organisation-wide")
                                   + ". Software updates also change fingerprints.",
                              observed={**observed, "org_known": org_known}, evidence_only=org_known)

    def commit(self, ctx, result, flagged):
        val = ctx.cache.get("d26")
        if not val or not ctx.f.entity_key or flagged:
            return
        key, ja3 = val
        st = ctx.baselines.get_state(ctx.f.entity_key, key)
        seen = st.setdefault("seen", {})
        seen[ja3] = seen.get(ja3, 0) + 1
        if len(seen) > 50:
            st["seen"] = dict(sorted(seen.items(), key=lambda kv: -kv[1])[:50])
        ctx.baselines.set_state(ctx.f.entity_key, key, st)
        org = ctx.baselines.get_state(ORG_ENTITY, self.ORG)
        lst = org.setdefault("ja3", [])
        if ja3 not in lst:
            lst.append(ja3)
            org["ja3"] = lst[-2000:]
            ctx.baselines.set_state(ORG_ENTITY, self.ORG, org)
