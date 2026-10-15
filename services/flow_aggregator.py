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

After a TCP close, the connection's trailing packets (the last ACK, retransmitted FINs)
arriving within CLOSE_GRACE_S are attributed to the closed flow (`late_packets`) instead
of opening a bogus one-packet flow. A SYN always starts a new flow.
"""
import hashlib
import math
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

FLAG_NAMES = {"S": "syn", "A": "ack", "F": "fin", "R": "rst", "P": "psh", "U": "urg"}
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


class _Flow:
    __slots__ = (
        "key", "flow_id", "protocol", "init_ip", "init_port", "resp_ip", "resp_port",
        "initiator_inferred", "start", "last", "fwd_packets", "bwd_packets", "fwd_bytes",
        "bwd_bytes", "sizes", "iat", "flags", "fin_from", "rst", "tls",
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
        self.fwd_packets = self.bwd_packets = 0
        self.fwd_bytes = self.bwd_bytes = 0
        self.sizes = _RunningStats()
        self.iat = _RunningStats()
        self.flags = {name: 0 for name in FLAG_NAMES.values()}
        self.fin_from = set()
        self.rst = False
        self.tls: Dict[str, Any] = {}

    def add(self, meta):
        ts = float(meta["timestamp"])
        if self.fwd_packets + self.bwd_packets > 0:
            self.iat.add(max(0.0, ts - self.last))
        self.last = max(self.last, ts)
        size = int(meta.get("bytes") or 0)
        self.sizes.add(size)
        forward = meta["src_ip"] == self.init_ip and meta.get("src_port") == self.init_port
        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size
        for letter in meta.get("tcp_flags") or "":
            name = FLAG_NAMES.get(letter)
            if name:
                self.flags[name] += 1
        if "F" in (meta.get("tcp_flags") or ""):
            self.fin_from.add("fwd" if forward else "bwd")
        if "R" in (meta.get("tcp_flags") or ""):
            self.rst = True
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

    @property
    def closed(self) -> bool:
        return self.rst or self.fin_from == {"fwd", "bwd"}

    def to_event(self, end_reason: str) -> Dict[str, Any]:
        total = self.fwd_packets + self.bwd_packets
        details = {
            "start_time": self.start,
            "end_time": self.last,
            "end_reason": end_reason,
            "initiator_inferred": self.initiator_inferred,
            "total_packets": total,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "total_bytes": self.fwd_bytes + self.bwd_bytes,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "packet_size": self.sizes.as_dict(2),
            "inter_arrival_s": self.iat.as_dict(6),
            "tcp_flags": dict(self.flags) if self.protocol == "TCP" else None,
        }
        if self.tls:
            details["tls"] = dict(self.tls)
        return {
            "event_type": "network_flow",
            "flow_id": self.flow_id,
            "timestamp": self.start,
            "src_ip": self.init_ip,
            "dst_ip": self.resp_ip,
            "src_port": self.init_port,
            "dst_port": self.resp_port,
            "protocol": self.protocol,
            "bytes": self.fwd_bytes + self.bwd_bytes,
            "pkts": total,
            "duration": round(self.last - self.start, 6),
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
