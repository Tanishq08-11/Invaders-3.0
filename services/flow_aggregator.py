"""
Bidirectional flow aggregation
===============================
Groups packet metadata (services/network_metadata.py) into bidirectional flows.

Canonical key: (protocol, lower endpoint, higher endpoint) where an endpoint is
(ip, port) — so A→B and B→A packets land in the same flow. The *initiator* (forward
direction) is the sender of a TCP SYN without ACK when one is seen, otherwise the sender
of the first packet observed (flagged with `initiator_inferred: true`).

A flow is emitted exactly once, when it completes:
  idle_timeout     no packet for FLOW_IDLE_TIMEOUT_S
  active_timeout   open longer than FLOW_ACTIVE_TIMEOUT_S (a new flow starts afterwards)
  tcp_close        FIN seen from both sides, or RST
  evicted          the table reached FLOW_MAX_TRACKED (least recently seen flow first)
  collector_stopped / pcap_end   explicit flush

Timeouts are evaluated against packet timestamps (so PCAP replays behave like live
capture) and, for live capture, against wall-clock time via `expire(now)`.

Measurements that were not observed are reported as null, never estimated; e.g. a
one-packet flow has null inter-arrival statistics.

Orientation: `fwd`/`bwd` are initiator→responder / responder→initiator. Organisation
direction (`org_direction`, `outbound_bytes`, `inbound_bytes`) is derived separately from
INTERNAL_NETWORKS: outbound bytes are what the internal endpoint sent to the external one,
whichever side opened the connection. Undefined (null) when both or neither side is internal.

Per-direction size and inter-arrival histograms use fixed bins (bounded memory) and carry
their Shannon entropy — no packet sequence or payload is retained.

After a TCP close, the connection's trailing packets (the last ACK, retransmitted FINs)
arriving within CLOSE_GRACE_S are attributed to the closed flow (`late_packets`) instead
of opening a bogus one-packet flow. A SYN always starts a new flow.
"""
import hashlib
import math
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from services.network_metadata import org_orientation

FLAG_NAMES = {"S": "syn", "A": "ack", "F": "fin", "R": "rst", "P": "psh", "U": "urg", "E": "ece"}
CLOSE_GRACE_S = 5.0


class _RunningStats:
    """Welford mean/variance plus min/max — O(1) memory per flow."""
    __slots__ = ("n", "mean", "m2", "min", "max")

    def __init__(self):
        self.n, self.mean, self.m2 = 0, 0.0, 0.0
        self.min = self.max = None

    def add(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        self.min = x if self.min is None else min(self.min, x)
        self.max = x if self.max is None else max(self.max, x)

    def as_dict(self, digits: int = 6) -> Dict[str, Optional[float]]:
        if self.n == 0:
            return {"min": None, "max": None, "mean": None, "std": None}
        std = math.sqrt(self.m2 / self.n) if self.n > 1 else 0.0
        return {
            "min": round(self.min, digits),
            "max": round(self.max, digits),
            "mean": round(self.mean, digits),
            "std": round(std, digits),
        }


def canonical_key(meta: Dict[str, Any]) -> Tuple:
    a = (meta["src_ip"], meta.get("src_port"))
    b = (meta["dst_ip"], meta.get("dst_port"))
    lo, hi = (a, b) if (str(a[0]), a[1] or 0) <= (str(b[0]), b[1] or 0) else (b, a)
    return (meta.get("protocol") or "OTHER", lo, hi)


# Fixed histogram edges (bounded memory; used for timing/size distribution statistics).
IAT_EDGES_S = (0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0)   # 14 bins
SIZE_EDGES_B = (64, 128, 256, 512, 768, 1024, 1280, 1400, 1500)                              # 10 bins
MAX_DNS_NAMES = 10


def _bin(value: float, edges) -> int:
    for i, edge in enumerate(edges):
        if value < edge:
            return i
    return len(edges)


def shannon_entropy(counts) -> Optional[float]:
    """Shannon entropy (bits) of a histogram; None for an empty histogram."""
    total = sum(counts)
    if total <= 0:
        return None
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def histogram_summary(counts, edges) -> Dict[str, Any]:
    h = shannon_entropy(counts)
    n_bins = len(edges) + 1
    return {
        "edges": list(edges),
        "counts": list(counts),
        "samples": int(sum(counts)),
        "entropy_bits": round(h, 4) if h is not None else None,
        # Entropy divided by log2(#bins): 0 = all samples in one bin, 1 = uniform.
        "entropy_normalized": round(h / math.log2(n_bins), 4) if h is not None else None,
    }


class _Side:
    """Per-direction statistics (initiator→responder or responder→initiator)."""
    __slots__ = ("packets", "bytes", "last_ts", "iat", "size_hist", "iat_hist", "payload_packets", "app_hint", "mac",
                 "sizes", "psh", "urg", "header_bytes", "header_packets", "init_window")

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.last_ts = None
        self.iat = _RunningStats()
        self.sizes = _RunningStats()
        self.psh = 0
        self.urg = 0
        self.header_bytes = 0
        self.header_packets = 0      # packets whose header length was reported
        self.init_window = None      # TCP window of this direction's first packet
        self.size_hist = [0] * (len(SIZE_EDGES_B) + 1)
        self.iat_hist = [0] * (len(IAT_EDGES_S) + 1)
        self.payload_packets = 0
        self.app_hint = None
        self.mac = None

    def add(self, ts: float, size: int, meta):
        if self.last_ts is not None:
            gap = max(0.0, ts - self.last_ts)
            self.iat.add(gap)
            self.iat_hist[_bin(gap, IAT_EDGES_S)] += 1
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        self.packets += 1
        self.bytes += size
        self.sizes.add(size)
        self.size_hist[_bin(size, SIZE_EDGES_B)] += 1
        flags = meta.get("tcp_flags") or ""
        self.psh += "P" in flags
        self.urg += "U" in flags
        if meta.get("header_bytes") is not None:
            self.header_bytes += int(meta["header_bytes"])
            self.header_packets += 1
        if self.packets == 1 and meta.get("tcp_window") is not None:
            self.init_window = int(meta["tcp_window"])
        if (meta.get("payload_bytes") or 0) > 0:
            self.payload_packets += 1
            if self.app_hint is None and meta.get("app_hint"):
                self.app_hint = meta["app_hint"]
        if self.mac is None and meta.get("src_mac"):
            self.mac = meta["src_mac"]

    def summary(self) -> Dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "payload_packets": self.payload_packets,
            "inter_arrival_s": self.iat.as_dict(6),
            "inter_arrival_total_s": round(self.iat.mean * self.iat.n, 6) if self.iat.n else None,
            "packet_size": self.sizes.as_dict(2),
            "psh_flags": self.psh,
            "urg_flags": self.urg,
            # Only defined when every packet of this direction reported its header length.
            "header_bytes": self.header_bytes if self.packets and self.header_packets == self.packets else None,
            "init_window": self.init_window,
            "iat_histogram": histogram_summary(self.iat_hist, IAT_EDGES_S),
            "size_histogram": histogram_summary(self.size_hist, SIZE_EDGES_B),
            "app_hint": self.app_hint,
        }


class _Flow:
    __slots__ = (
        "key", "flow_id", "protocol", "init_ip", "init_port", "resp_ip", "resp_port",
        "initiator_inferred", "start", "last", "fwd", "bwd", "sizes", "iat", "flags",
        "fin_from", "rst_from", "syn_fwd", "synack_bwd", "tls", "dns",
    )

    def __init__(self, key, meta):
        self.key = key
        self.protocol = meta.get("protocol") or "OTHER"
        flags = meta.get("tcp_flags") or ""
        self.init_ip, self.init_port = meta["src_ip"], meta.get("src_port")
        self.resp_ip, self.resp_port = meta["dst_ip"], meta.get("dst_port")
        # Only a bare SYN proves who opened a TCP connection.
        self.initiator_inferred = not (self.protocol == "TCP" and "S" in flags and "A" not in flags)
        self.start = self.last = float(meta["timestamp"])
        self.flow_id = hashlib.sha1(f"{key}|{self.start:.6f}".encode()).hexdigest()[:32]
        self.fwd, self.bwd = _Side(), _Side()
        self.sizes = _RunningStats()
        self.iat = _RunningStats()
        self.flags = {name: 0 for name in FLAG_NAMES.values()}
        self.fin_from = set()
        self.rst_from = set()
        self.syn_fwd = False
        self.synack_bwd = False
        self.tls: Dict[str, Any] = {}
        self.dns: Optional[Dict[str, Any]] = None

    # Back-compat accessors used by callers/tests
    @property
    def fwd_packets(self):
        return self.fwd.packets

    @property
    def bwd_packets(self):
        return self.bwd.packets

    def add(self, meta):
        ts = float(meta["timestamp"])
        if self.fwd.packets + self.bwd.packets > 0:
            self.iat.add(max(0.0, ts - self.last))
        self.last = max(self.last, ts)
        size = int(meta.get("bytes") or 0)
        self.sizes.add(size)
        forward = meta["src_ip"] == self.init_ip and meta.get("src_port") == self.init_port
        (self.fwd if forward else self.bwd).add(ts, size, meta)
        flags = meta.get("tcp_flags") or ""
        for letter in flags:
            name = FLAG_NAMES.get(letter)
            if name:
                self.flags[name] += 1
        if "S" in flags and "A" not in flags and forward:
            self.syn_fwd = True
        if "S" in flags and "A" in flags and not forward:
            self.synack_bwd = True
        if "F" in flags:
            self.fin_from.add("fwd" if forward else "bwd")
        if "R" in flags:
            self.rst_from.add("fwd" if forward else "bwd")
        tls = meta.get("tls")
        if tls:
            # Keep the first ClientHello / ServerHello fields; never overwrite with later ones.
            side = "client" if tls.get("handshake") == "client_hello" else "server"
            for k, v in tls.items():
                if k in ("handshake", "complete", "extraction_source"):
                    continue
                self.tls.setdefault(k if k in ("sni", "ja3", "ja3_string") else f"{side}_{k}", v)
            self.tls.setdefault("extraction_source", tls.get("extraction_source", "builtin"))
            self.tls[f"{side}_hello_complete"] = bool(tls.get("complete"))
        dns = meta.get("dns")
        if dns:
            d = self.dns or {"queries": 0, "responses": 0, "nxdomain": 0, "qtypes": {}, "names": [], "answers": 0}
            if dns.get("is_response"):
                d["responses"] += 1
                d["answers"] += int(dns.get("answers") or 0)
                if dns.get("rcode") == "NXDOMAIN":
                    d["nxdomain"] += 1
            else:
                d["queries"] += 1
                qt = str(dns.get("qtype"))
                d["qtypes"][qt] = d["qtypes"].get(qt, 0) + 1
            name = dns.get("qname")
            if name and name not in d["names"] and len(d["names"]) < MAX_DNS_NAMES:
                d["names"].append(name)
            self.dns = d

    @property
    def closed(self) -> bool:
        return bool(self.rst_from) or self.fin_from == {"fwd", "bwd"}

    def tcp_outcome(self) -> Optional[str]:
        if self.protocol != "TCP":
            return None
        if self.synack_bwd:
            return "established"
        if self.syn_fwd and self.bwd.packets == 0:
            return "no_response"
        if self.syn_fwd and "bwd" in self.rst_from:
            return "rejected"
        if self.fwd.packets and self.bwd.packets:
            return "established_midstream"   # handshake not observed (capture started mid-connection)
        return "partial"

    def to_event(self, end_reason: str) -> Dict[str, Any]:
        total = self.fwd.packets + self.bwd.packets
        orient = org_orientation(self.init_ip, self.resp_ip)
        side = orient["internal_side"]
        # Organisation-relative bytes: what the internal endpoint sent out vs received,
        # regardless of which side initiated. Only defined with exactly one internal side.
        if side == "a":
            out_s, in_s, internal_ip, external_ip = self.fwd, self.bwd, self.init_ip, self.resp_ip
        elif side == "b":
            out_s, in_s, internal_ip, external_ip = self.bwd, self.fwd, self.resp_ip, self.init_ip
        else:
            out_s = in_s = None
            internal_ip = self.init_ip if side == "both" else None
            external_ip = None
        details = {
            "start_time": self.start,
            "end_time": self.last,
            "duration_s": round(self.last - self.start, 6),
            "end_reason": end_reason,
            "initiator_inferred": self.initiator_inferred,
            "org_direction": orient["direction"],
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "outbound_bytes": out_s.bytes if out_s else None,
            "inbound_bytes": in_s.bytes if in_s else None,
            "outbound_packets": out_s.packets if out_s else None,
            "inbound_packets": in_s.packets if in_s else None,
            "total_packets": total,
            "fwd_packets": self.fwd.packets,
            "bwd_packets": self.bwd.packets,
            "total_bytes": self.fwd.bytes + self.bwd.bytes,
            "fwd_bytes": self.fwd.bytes,
            "bwd_bytes": self.bwd.bytes,
            "packet_size": self.sizes.as_dict(2),
            "inter_arrival_s": self.iat.as_dict(6),
            "fwd": self.fwd.summary(),
            "bwd": self.bwd.summary(),
            "tcp_flags": dict(self.flags) if self.protocol == "TCP" else None,
            "tcp_outcome": self.tcp_outcome(),
            "app_protocol": ("dns" if self.dns else None) or self.fwd.app_hint or self.bwd.app_hint,
            "init_mac": self.fwd.mac,
            "resp_mac": self.bwd.mac,
        }
        if self.tls:
            details["tls"] = dict(self.tls)
        if self.dns:
            details["dns"] = dict(self.dns)
        return {
            "event_type": "network_flow",
            "flow_id": self.flow_id,
            "timestamp": self.start,
            "src_ip": self.init_ip,
            "dst_ip": self.resp_ip,
            "src_port": self.init_port,
            "dst_port": self.resp_port,
            "protocol": self.protocol,
            "bytes": self.fwd.bytes + self.bwd.bytes,
            "pkts": total,
            "duration": round(self.last - self.start, 6),
            "direction": orient["direction"],
            "details": details,
        }


class FlowAggregator:
    def __init__(self, idle_timeout: float = 30.0, active_timeout: float = 300.0, max_flows: int = 10000):
        self.idle_timeout = float(idle_timeout)
        self.active_timeout = float(active_timeout)
        self.max_flows = max(1, int(max_flows))
        self._flows: "OrderedDict[Tuple, _Flow]" = OrderedDict()  # ordered by last activity
        self._closed: "OrderedDict[Tuple, Tuple[str, float]]" = OrderedDict()  # key -> (flow_id, closed at)
        self._lock = threading.Lock()
        self.late_packets = 0
        self.flows_emitted = 0
        self.flows_evicted = 0
        self.packets_aggregated = 0
        self.packets_rejected = 0

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    def update(self, meta: Dict[str, Any]) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Add one packet. Returns (flow_id of the packet's flow, completed flows to emit).
        Packets without usable addresses or timestamps are rejected (flow_id None).
        """
        try:
            ts = float(meta["timestamp"])
            if not meta.get("src_ip") or not meta.get("dst_ip") or math.isnan(ts):
                raise ValueError("missing address")
            key = canonical_key(meta)
        except (KeyError, TypeError, ValueError):
            with self._lock:
                self.packets_rejected += 1
            return None, []

        completed: List[Dict[str, Any]] = []
        with self._lock:
            completed.extend(self._expire_locked(ts))
            tomb = self._closed.get(key)
            if tomb is not None and key not in self._flows:
                if ts - tomb[1] <= CLOSE_GRACE_S and "S" not in (meta.get("tcp_flags") or ""):
                    self.late_packets += 1
                    return tomb[0], completed
                del self._closed[key]
            flow = self._flows.get(key)
            if flow is not None and ts - flow.start >= self.active_timeout:
                completed.append(self._pop_locked(key, "active_timeout"))
                flow = None
            if flow is None:
                if len(self._flows) >= self.max_flows:
                    oldest = next(iter(self._flows))
                    completed.append(self._pop_locked(oldest, "evicted"))
                    self.flows_evicted += 1
                flow = _Flow(key, meta)
                self._flows[key] = flow
            flow.add(meta)
            self._flows.move_to_end(key)
            self.packets_aggregated += 1
            flow_id = flow.flow_id
            if flow.closed:
                completed.append(self._pop_locked(key, "tcp_close"))
                self._closed[key] = (flow_id, ts)
                while len(self._closed) > self.max_flows:
                    self._closed.popitem(last=False)
        return flow_id, completed

    def expire(self, now: float) -> List[Dict[str, Any]]:
        with self._lock:
            return self._expire_locked(now)

    def flush(self, reason: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._pop_locked(k, reason) for k in list(self._flows)]

    def _expire_locked(self, now: float) -> List[Dict[str, Any]]:
        while self._closed:
            key, (_, closed_at) = next(iter(self._closed.items()))
            if now - closed_at <= CLOSE_GRACE_S:
                break
            del self._closed[key]
        out = []
        # Ordered by last activity, so stop at the first flow that is still fresh
        # (active timeouts on long-lived flows are applied when their next packet arrives).
        for key in list(self._flows):
            flow = self._flows[key]
            if now - flow.last >= self.idle_timeout:
                out.append(self._pop_locked(key, "idle_timeout"))
            elif now - flow.start >= self.active_timeout:
                out.append(self._pop_locked(key, "active_timeout"))
            else:
                break
        return out

    def _pop_locked(self, key, reason) -> Dict[str, Any]:
        flow = self._flows.pop(key)
        self.flows_emitted += 1
        return flow.to_event(reason)

    def stats(self) -> Dict[str, Any]:
        return {
            "active_flows": self.active_flows,
            "flows_emitted": self.flows_emitted,
            "flows_evicted": self.flows_evicted,
            "packets_aggregated": self.packets_aggregated,
            "packets_rejected": self.packets_rejected,
            "late_packets": self.late_packets,
            "idle_timeout_s": self.idle_timeout,
            "active_timeout_s": self.active_timeout,
            "max_flows": self.max_flows,
        }
