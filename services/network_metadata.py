"""
Packet header metadata extraction (zero decryption, no payload retention)
==========================================================================
Turns one Scapy packet into a flat metadata dict:

  timestamp, ip_version, src_ip, dst_ip, src_port, dst_port, protocol,
  bytes (wire length), payload_bytes (size only), tcp_flags, direction, tls?

The only payload bytes ever inspected are the first bytes of a TCP segment that starts
with a TLS handshake record, and only to read cleartext ClientHello / ServerHello header
fields (services/tls_metadata.py). Payload content is never copied into the result.
"""
import ipaddress
import os
import time
from typing import Any, Dict, Optional

from services.tls_metadata import looks_like_tls_handshake, parse_tls_handshake

try:  # Scapy is optional at import time so the API still starts without it.
    from scapy.all import ICMP, IP, IPv6, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only on hosts without scapy
    IP = IPv6 = TCP = UDP = ICMP = None
    SCAPY_AVAILABLE = False

# Scapy flag letters in a stable order (FIN SYN RST PSH ACK URG ECE CWR).
TCP_FLAG_LETTERS = "FSRPAUEC"
_TLS_PEEK_BYTES = 4096


# Address space treated as "inside the organisation" for direction / external checks.
# Explicit list (not ipaddress.is_private, which also covers documentation and other
# special-purpose ranges). Override with INTERNAL_NETWORKS="10.0.0.0/8,192.168.0.0/16,…".
_DEFAULT_INTERNAL = (
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,"
    "::1/128,fe80::/10,fc00::/7"
)
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n.strip(), strict=False)
    for n in os.environ.get("INTERNAL_NETWORKS", _DEFAULT_INTERNAL).split(",") if n.strip()
]


def _is_internal(ip: str) -> Optional[bool]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(addr.version == net.version and addr in net for net in INTERNAL_NETWORKS)


def classify_direction(src_ip: str, dst_ip: str) -> Optional[str]:
    """outbound / inbound / internal / external relative to private address space."""
    s, d = _is_internal(src_ip), _is_internal(dst_ip)
    if s is None or d is None:
        return None
    if s and d:
        return "internal"
    if s and not d:
        return "outbound"
    if not s and d:
        return "inbound"
    return "external"


def is_external(ip: Optional[str]) -> bool:
    return bool(ip) and _is_internal(ip) is False


def tcp_flag_string(flags) -> str:
    """Normalise Scapy's FlagValue / int to letters like 'SA' (order FSRPAUEC)."""
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return ""
    return "".join(letter for i, letter in enumerate(TCP_FLAG_LETTERS) if value & (1 << i))


def extract_packet_metadata(pkt) -> Optional[Dict[str, Any]]:
    """
    Header metadata for one packet, or None for non-IP frames and packets whose
    headers cannot be read. Never raises.
    """
    if not SCAPY_AVAILABLE:
        return None
    try:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ip_version = 4
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            ip_version = 6
        else:
            return None  # ARP, raw Ethernet, …
        src_ip, dst_ip = str(ip.src), str(ip.dst)

        src_port = dst_port = None
        tcp_flags = None
        payload_len = 0
        tls = None
        if pkt.haslayer(TCP):
            seg = pkt[TCP]
            proto = "TCP"
            src_port, dst_port = int(seg.sport), int(seg.dport)
            tcp_flags = tcp_flag_string(seg.flags)
            payload = bytes(seg.payload)[:_TLS_PEEK_BYTES] if seg.payload is not None else b""
            payload_len = len(seg.payload) if seg.payload is not None else 0
            if looks_like_tls_handshake(payload):
                tls = parse_tls_handshake(payload)
            del payload  # never retained
        elif pkt.haslayer(UDP):
            dgram = pkt[UDP]
            proto = "UDP"
            src_port, dst_port = int(dgram.sport), int(dgram.dport)
            payload_len = len(dgram.payload) if dgram.payload is not None else 0
        elif ICMP is not None and pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"

        meta = {
            "timestamp":     float(getattr(pkt, "time", None) or time.time()),
            "ip_version":    ip_version,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "src_port":      src_port,
            "dst_port":      dst_port,
            "protocol":      proto,
            "bytes":         int(len(pkt)),
            "payload_bytes": int(payload_len),
            "pkts":          1,
            "duration":      0.0,
            "tcp_flags":     tcp_flags,
            "direction":     classify_direction(src_ip, dst_ip),
        }
        if tls:
            meta["tls"] = {**tls, "extraction_source": "builtin"}
        return meta
    except Exception:
        # Truncated / corrupted headers: the caller counts it as malformed.
        return None
