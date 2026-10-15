"""
Packet header metadata extraction (zero decryption, no payload retention)
==========================================================================
Turns one Scapy packet into a flat metadata dict:

  timestamp, ip_version, src_ip, dst_ip, src_port, dst_port, protocol,
  bytes (wire length), payload_bytes (size only), tcp_flags, direction,
  src_mac/dst_mac (only when an Ethernet header is present), app_hint, tls?, dns?

Payload handling:
  • TCP segments starting with a TLS handshake record: cleartext ClientHello /
    ServerHello header fields are parsed (services/tls_metadata.py).
  • The first bytes of a TCP payload are compared against fixed protocol signatures
    ("SSH-", HTTP method tokens) to set `app_hint`; only the label is kept.
  • Cleartext DNS on port 53 (UDP/TCP): query name, type, response code and answer
    count. DNS over HTTPS / TLS is encrypted and is never inspected.
Payload content is never copied into the result.

MAC addresses are link-layer observations from the capture point: absent for many
capture types, the router's address for off-segment hosts, and spoofable — they are
recorded as metadata, never as proof of identity.
"""
import ipaddress
import os
import time
from typing import Any, Dict, Optional

from services.tls_metadata import looks_like_tls_handshake, parse_tls_handshake

try:  # Scapy is optional at import time so the API still starts without it.
    from scapy.all import ICMP, IP, IPv6, TCP, UDP, Ether
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only on hosts without scapy
    IP = IPv6 = TCP = UDP = ICMP = Ether = DNS = None
    SCAPY_AVAILABLE = False

DNS_PORT = 53
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

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


def is_internal(ip: Optional[str]) -> bool:
    return bool(ip) and _is_internal(ip) is True


def org_orientation(a_ip: Optional[str], b_ip: Optional[str]) -> Dict[str, Any]:
    """
    Organisation-relative orientation of a connection between endpoints a (initiator)
    and b (responder) — independent of which side sent first:
      direction      outbound (internal→external initiated), inbound, internal, external, unknown
      internal_side  "a" | "b" | "both" | None
    """
    ia, ib = (_is_internal(a_ip) if a_ip else None), (_is_internal(b_ip) if b_ip else None)
    if ia is None or ib is None:
        return {"direction": "unknown", "internal_side": None}
    if ia and ib:
        return {"direction": "internal", "internal_side": "both"}
    if ia:
        return {"direction": "outbound", "internal_side": "a"}
    if ib:
        return {"direction": "inbound", "internal_side": "b"}
    return {"direction": "external", "internal_side": None}


def tcp_flag_string(flags) -> str:
    """Normalise Scapy's FlagValue / int to letters like 'SA' (order FSRPAUEC)."""
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return ""
    return "".join(letter for i, letter in enumerate(TCP_FLAG_LETTERS) if value & (1 << i))


def app_hint(payload: bytes) -> Optional[str]:
    """Protocol label from fixed leading signatures; the bytes themselves are not kept."""
    if not payload:
        return None
    if looks_like_tls_handshake(payload) or (len(payload) >= 3 and payload[0] in (20, 21, 23) and payload[1] == 3):
        return "tls"
    if payload.startswith(b"SSH-"):
        return "ssh"
    if payload.startswith(_HTTP_METHODS) or payload.startswith(b"HTTP/1."):
        return "http"
    return "unknown"


def extract_dns(pkt) -> Optional[Dict[str, Any]]:
    """Cleartext DNS header + first question. Returns None when no DNS layer parses."""
    if DNS is None or not pkt.haslayer(DNS):
        return None
    try:
        dns = pkt[DNS]
        qd = dns.qd
        if isinstance(qd, (list, tuple)):
            qd = qd[0] if qd else None
        elif qd is not None and hasattr(qd, "__len__") and not hasattr(qd, "qname"):
            qd = qd[0] if len(qd) else None
        qname = qtype = None
        if qd is not None and getattr(qd, "qname", None) is not None:
            raw = qd.qname
            qname = (raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else str(raw)).rstrip(".").lower()[:255]
            qtype = int(qd.qtype)
        return {
            "is_response": bool(dns.qr),
            "rcode": DNS_RCODES.get(int(dns.rcode), str(int(dns.rcode))),
            "qname": qname,
            "qtype": qtype,
            "answers": int(dns.ancount or 0),
        }
    except Exception:
        return None


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
        hint = None
        if pkt.haslayer(TCP):
            seg = pkt[TCP]
            proto = "TCP"
            src_port, dst_port = int(seg.sport), int(seg.dport)
            tcp_flags = tcp_flag_string(seg.flags)
            payload = bytes(seg.payload)[:_TLS_PEEK_BYTES] if seg.payload is not None else b""
            payload_len = len(seg.payload) if seg.payload is not None else 0
            if looks_like_tls_handshake(payload):
                tls = parse_tls_handshake(payload)
            if DNS_PORT not in (src_port, dst_port):
                hint = app_hint(payload)
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
        if Ether is not None and pkt.haslayer(Ether):
            meta["src_mac"] = str(pkt[Ether].src).lower()
            meta["dst_mac"] = str(pkt[Ether].dst).lower()
        if hint:
            meta["app_hint"] = hint
        if tls:
            meta["tls"] = {**tls, "extraction_source": "builtin"}
        if DNS_PORT in (src_port, dst_port):
            dns = extract_dns(pkt)
            if dns:
                meta["dns"] = dns
                meta["app_hint"] = "dns"
        return meta
    except Exception:
        # Truncated / corrupted headers: the caller counts it as malformed.
        return None
