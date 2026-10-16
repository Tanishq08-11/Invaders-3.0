"""
Canonical flow feature builder for the TrustLab KitNET bundle
==============================================================
Turns one stored flow (aggregator `network_flow`) or flow record (`network_record`)
into the EXACT 78-feature vector, in the order stored in the bundle's `feature_names`:

    74 CICFlowMeter-style flow features  +  HourSin, HourCos, DaySin, DayCos

Units follow the bundle's training data (verified from the per-feature min/max the
autoencoders were normalised with): durations and inter-arrival times in MICROSECONDS,
Active/Idle statistics in SECONDS, packet lengths as whole frame sizes, header length
as network + transport header bytes.

Every feature is labelled with how its value was obtained — nothing is guessed:

  observed            measured by the flow aggregator (or present, by its exact
                      CICFlowMeter column name, in a supplied record)
  zero_by_definition  a statistic over an empty set (no packets in a direction, no
                      inter-arrival gap, no TCP flags on a non-TCP flow) — CICFlowMeter
                      emits 0 for these, and so does this builder
  imputed             not measured by this pipeline, or undefined for this flow (e.g. a
                      rate over a zero-length flow): the bundle's stored training median
                      is used, which is the bundle's own missing-value preprocessing

Not measured by this pipeline (always imputed): the six bulk-transfer features and the
eight Active/Idle features. Rule-detector outputs (D1–D28) are NEVER model inputs.

Time features: hour = h + m/60 + s/3600 and weekday Monday=0 (pandas `dayofweek`), in
TRUSTLAB_TIMEZONE, encoded as sin/cos(2π·hour/24) and sin/cos(2π·weekday/7).
"""
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

OBSERVED, ZERO, IMPUTED = "observed", "zero_by_definition", "imputed"
US = 1e6   # seconds → microseconds
PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}
NOT_MEASURED = (
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
)


@dataclass
class FeatureVector:
    names: List[str]
    values: np.ndarray
    sources: Dict[str, str]
    reasons: Dict[str, str] = field(default_factory=dict)   # why a feature was imputed

    def names_by(self, source: str) -> List[str]:
        return [n for n in self.names if self.sources[n] == source]

    def coverage(self) -> Dict[str, Any]:
        return {
            "total": len(self.names),
            "observed": len(self.names_by(OBSERVED)),
            "zero_by_definition": len(self.names_by(ZERO)),
            "imputed": len(self.names_by(IMPUTED)),
            "imputed_features": self.names_by(IMPUTED),
        }


def _num(v) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _tz(name: Optional[str]):
    if not name or name.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return timezone.utc


_TS_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S",
               "%Y-%m-%d %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p")


def parse_timestamp(value, tz_name: Optional[str] = None) -> Optional[float]:
    """
    One timestamp interpretation for every entry point (live flows, PCAP, records, /model/predict):
    epoch seconds (or ms), ISO-8601, or CICFlowMeter "dd/mm/YYYY HH:MM:SS". A string without an
    offset is read in TRUSTLAB_TIMEZONE — the same zone the time features are computed in.
    """
    if value is None or value == "":
        return None
    v = _num(value)
    if v is not None:
        if v > 1e11:          # milliseconds
            v /= 1000.0
        return v if v > 0 else None
    text = str(value).strip()
    tz = _tz(tz_name)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.timestamp()


def time_features(ts: Optional[float], tz_name: Optional[str] = None) -> Dict[str, Optional[float]]:
    if ts is None or ts <= 0:
        return {"HourSin": None, "HourCos": None, "DaySin": None, "DayCos": None}
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(_tz(tz_name))
    hour = dt.hour + dt.minute / 60.0 + dt.second / 3600.0
    day = dt.weekday()
    return {
        "HourSin": math.sin(2 * math.pi * hour / 24.0), "HourCos": math.cos(2 * math.pi * hour / 24.0),
        "DaySin": math.sin(2 * math.pi * day / 7.0), "DayCos": math.cos(2 * math.pi * day / 7.0),
    }


class _Builder:
    def __init__(self):
        self.vals: Dict[str, Optional[float]] = {}
        self.src: Dict[str, str] = {}
        self.reasons: Dict[str, str] = {}

    def obs(self, name, value, zero_if_empty: bool = False):
        v = _num(value)
        if v is not None:
            self.vals[name], self.src[name] = v, OBSERVED
        elif zero_if_empty:
            self.vals[name], self.src[name] = 0.0, ZERO

    def zero(self, name):
        self.vals[name], self.src[name] = 0.0, ZERO

    def missing(self, name, reason):
        self.reasons.setdefault(name, reason)


def _side_stats(b: _Builder, prefix: str, side: Dict[str, Any], packets: int, is_tcp: bool):
    """Per-direction (Fwd/Bwd) packet length, IAT, flag and header statistics."""
    p = "Fwd" if prefix == "fwd" else "Bwd"
    size = side.get("packet_size") or {}
    if packets == 0:
        for n in (f"{p} Pkt Len Max", f"{p} Pkt Len Min", f"{p} Pkt Len Mean", f"{p} Pkt Len Std",
                  f"{p} Seg Size Avg", f"{p} Header Len"):
            b.zero(n)
    elif size:
        b.obs(f"{p} Pkt Len Max", size.get("max"))
        b.obs(f"{p} Pkt Len Min", size.get("min"))
        b.obs(f"{p} Pkt Len Mean", size.get("mean"))
        b.obs(f"{p} Pkt Len Std", size.get("std"))
        b.obs(f"{p} Seg Size Avg", size.get("mean"))
    else:
        for n in (f"{p} Pkt Len Max", f"{p} Pkt Len Min", f"{p} Pkt Len Mean", f"{p} Pkt Len Std", f"{p} Seg Size Avg"):
            b.missing(n, "per-direction packet sizes not recorded for this flow")
    if packets:
        if side.get("header_bytes") is not None:
            b.obs(f"{p} Header Len", side["header_bytes"])
        else:
            b.missing(f"{p} Header Len", "header lengths not reported for every packet")

    iat = side.get("inter_arrival_s") or {}
    if packets < 2:
        for n in ("Tot", "Mean", "Std", "Max", "Min"):
            b.zero(f"{p} IAT {n}")
    elif iat.get("mean") is not None:
        b.obs(f"{p} IAT Tot", (side.get("inter_arrival_total_s") if side.get("inter_arrival_total_s") is not None
                               else iat["mean"] * (packets - 1)) * US)
        b.obs(f"{p} IAT Mean", iat["mean"] * US)
        b.obs(f"{p} IAT Std", (iat.get("std") or 0.0) * US)
        b.obs(f"{p} IAT Max", iat["max"] * US)
        b.obs(f"{p} IAT Min", iat["min"] * US)

    if not is_tcp:
        b.zero(f"{p} PSH Flags")
        b.zero(f"{p} URG Flags")
    else:
        b.obs(f"{p} PSH Flags", side.get("psh_flags"))
        b.obs(f"{p} URG Flags", side.get("urg_flags"))
        if side.get("init_window") is not None:
            b.obs(f"Init {p} Win Byts", side["init_window"])
        elif packets:
            b.missing(f"Init {p} Win Byts", "TCP window not recorded for this direction's first packet")
    if not is_tcp:
        b.missing(f"Init {p} Win Byts", "no TCP window on a non-TCP flow")


def _from_flow(b: _Builder, ev_cols: Dict[str, Any], d: Dict[str, Any], port_orientation: str = "service_src"):
    proto = (ev_cols.get("protocol") or "").upper()
    is_tcp = proto == "TCP"
    if port_orientation == "initiator":
        b.obs("Src Port", ev_cols.get("src_port"))
        b.obs("Dst Port", ev_cols.get("dst_port"))
    else:   # service_src: the bundle's training data has the service port in "Src Port"
        b.obs("Src Port", ev_cols.get("dst_port"))
        b.obs("Dst Port", ev_cols.get("src_port"))
    if proto in PROTOCOL_NUMBERS:
        b.vals["Protocol"], b.src["Protocol"] = float(PROTOCOL_NUMBERS[proto]), OBSERVED
    else:
        b.missing("Protocol", f"protocol {proto or 'unknown'} has no IANA number mapping here")

    dur = _num(d.get("duration_s", ev_cols.get("duration")))
    fwd_p, bwd_p = int(d.get("fwd_packets") or 0), int(d.get("bwd_packets") or 0)
    fwd_b, bwd_b = _num(d.get("fwd_bytes")), _num(d.get("bwd_bytes"))
    total_p = fwd_p + bwd_p
    total_b = (fwd_b or 0.0) + (bwd_b or 0.0)
    if dur is not None:
        b.obs("Flow Duration", dur * US)
    b.obs("Tot Fwd Pkts", fwd_p)
    b.obs("Tot Bwd Pkts", bwd_p)
    b.obs("TotLen Fwd Pkts", fwd_b)
    b.obs("TotLen Bwd Pkts", bwd_b)
    # One subflow per flow (the bundle's training data has Subflow == Tot for the median flow).
    b.obs("Subflow Fwd Pkts", fwd_p)
    b.obs("Subflow Bwd Pkts", bwd_p)
    b.obs("Subflow Fwd Byts", fwd_b)
    b.obs("Subflow Bwd Byts", bwd_b)

    ps = d.get("packet_size") or {}
    if ps.get("mean") is not None:
        b.obs("Pkt Len Min", ps.get("min"))
        b.obs("Pkt Len Max", ps.get("max"))
        b.obs("Pkt Len Mean", ps.get("mean"))
        b.obs("Pkt Len Std", ps.get("std"))
        if ps.get("std") is not None:
            b.obs("Pkt Len Var", float(ps["std"]) ** 2)
    if total_p:
        b.obs("Pkt Size Avg", total_b / total_p)

    if dur and dur > 0:
        b.obs("Flow Pkts/s", total_p / dur)
        b.obs("Flow Byts/s", total_b / dur)
    else:
        b.missing("Flow Pkts/s", "rate undefined for a zero-length flow")
        b.missing("Flow Byts/s", "rate undefined for a zero-length flow")

    iat = d.get("inter_arrival_s") or {}
    if total_p < 2:
        for n in ("Mean", "Std", "Max", "Min"):
            b.zero(f"Flow IAT {n}")
    elif iat.get("mean") is not None:
        b.obs("Flow IAT Mean", iat["mean"] * US)
        b.obs("Flow IAT Std", (iat.get("std") or 0.0) * US)
        b.obs("Flow IAT Max", iat["max"] * US)
        b.obs("Flow IAT Min", iat["min"] * US)

    _side_stats(b, "fwd", d.get("fwd") or {}, fwd_p, is_tcp)
    _side_stats(b, "bwd", d.get("bwd") or {}, bwd_p, is_tcp)

    flags = d.get("tcp_flags")
    names = {"FIN Flag Cnt": "fin", "SYN Flag Cnt": "syn", "RST Flag Cnt": "rst", "PSH Flag Cnt": "psh",
             "ACK Flag Cnt": "ack", "URG Flag Cnt": "urg", "ECE Flag Cnt": "ece"}
    for feat, key in names.items():
        if not is_tcp:
            b.zero(feat)
        elif isinstance(flags, dict) and key in flags:
            b.obs(feat, flags[key])
        else:
            b.missing(feat, "TCP flag counts not recorded for this flow")
    b.obs("Down/Up Ratio", bwd_p / fwd_p if fwd_p else None, zero_if_empty=True)


def _from_record(b: _Builder, ev_cols: Dict[str, Any], raw: Dict[str, Any], feature_names: List[str]):
    """Records contribute only fields carrying the exact CICFlowMeter column name (case/space-insensitive)."""
    lookup = {str(k).strip().lower(): v for k, v in (raw or {}).items()}
    for name in feature_names:
        if name in ("HourSin", "HourCos", "DaySin", "DayCos"):
            continue
        v = lookup.get(name.lower())
        if v is not None:
            b.obs(name, v)
    if "Src Port" not in b.src:
        b.obs("Src Port", ev_cols.get("src_port"))
    if "Dst Port" not in b.src:
        b.obs("Dst Port", ev_cols.get("dst_port"))
    if "Protocol" not in b.src:
        proto = str(ev_cols.get("protocol") or lookup.get("protocol") or "").upper()
        if proto in PROTOCOL_NUMBERS:
            b.vals["Protocol"], b.src["Protocol"] = float(PROTOCOL_NUMBERS[proto]), OBSERVED


def build_feature_vector(
    *,
    event_type: str,
    columns: Dict[str, Any],
    details: Optional[Dict[str, Any]],
    raw_record: Optional[Dict[str, Any]],
    feature_names: List[str],
    medians: Dict[str, float],
    tz_name: Optional[str] = None,
    port_orientation: str = "service_src",
) -> FeatureVector:
    """
    columns: src_port, dst_port, protocol, duration, timestamp (epoch seconds of the flow start).
    Produces values in `feature_names` order; anything not observed gets the bundle median.
    """
    if len(feature_names) != 78 or list(feature_names[-4:]) != ["HourSin", "HourCos", "DaySin", "DayCos"]:
        raise ValueError(f"TrustLab schema violated: {len(feature_names)} feature names")
    b = _Builder()
    ts = parse_timestamp(columns.get("timestamp"), tz_name)
    if event_type == "network_flow":
        _from_flow(b, columns, details or {}, port_orientation)
    else:
        _from_record(b, columns, raw_record or {}, feature_names)
        if ts is None:
            lookup = {str(k).strip().lower(): v for k, v in (raw_record or {}).items()}
            ts = parse_timestamp(lookup.get("timestamp"), tz_name)
    for name, v in time_features(ts, tz_name).items():
        if v is not None:
            b.vals[name], b.src[name] = v, OBSERVED
        else:
            b.missing(name, "event timestamp unavailable")
    for name in NOT_MEASURED:
        b.missing(name, "not measured by this pipeline's flow aggregator")

    values = np.zeros(len(feature_names), dtype=np.float64)
    sources: Dict[str, str] = {}
    reasons: Dict[str, str] = {}
    for i, name in enumerate(feature_names):
        if name in b.src and b.vals.get(name) is not None:
            values[i], sources[name] = b.vals[name], b.src[name]
        else:
            values[i] = float(medians.get(name, 0.0))
            sources[name] = IMPUTED
            reasons[name] = b.reasons.get(name, "not present in this event")
    assert values.shape == (78,), f"TrustLab feature vector must be (78,), got {values.shape}"
    return FeatureVector(names=list(feature_names), values=values, sources=sources, reasons=reasons)


def build_from_cic_record(flow: Dict[str, Any], feature_names: List[str], medians: Dict[str, float],
                          tz_name: Optional[str] = None) -> FeatureVector:
    """Entry point for /model/predict(/batch): a CICFlowMeter-named dict, through the same builder."""
    lookup = {str(k).strip().lower(): v for k, v in flow.items()}
    columns = {"src_port": lookup.get("src port", lookup.get("src_port")),
               "dst_port": lookup.get("dst port", lookup.get("dst_port")),
               "protocol": lookup.get("protocol"),
               "timestamp": lookup.get("timestamp")}
    return build_feature_vector(event_type="network_record", columns=columns, details=None, raw_record=flow,
                                feature_names=feature_names, medians=medians, tz_name=tz_name)
