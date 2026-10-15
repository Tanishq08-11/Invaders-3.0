"""Builders for synthetic packets and TLS handshakes used by the pipeline tests."""
import struct

from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw

# JA3 reference vector from the JA3 specification (salesforce/ja3 README).
JA3_REFERENCE_STRING = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
JA3_REFERENCE_MD5 = "ada70206e40642a3e4461f35503241d5"
REFERENCE_CIPHERS = (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4)


def ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


def sni_ext(name: str) -> bytes:
    entry = b"\x00" + struct.pack("!H", len(name)) + name.encode()
    return ext(0, struct.pack("!H", len(entry)) + entry)


def groups_ext(groups) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in groups)
    return ext(10, struct.pack("!H", len(body)) + body)


def point_formats_ext(formats) -> bytes:
    return ext(11, bytes([len(formats)]) + bytes(formats))


def client_hello(version=0x0301, ciphers=REFERENCE_CIPHERS, extensions=None, record_version=0x0301) -> bytes:
    if extensions is None:
        extensions = [sni_ext("files.example.com"), groups_ext((23, 24, 25)), point_formats_ext((0,))]
    body = struct.pack("!H", version) + b"\x11" * 32 + b"\x00"
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"
    ext_bytes = b"".join(extensions)
    body += struct.pack("!H", len(ext_bytes)) + ext_bytes
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!H", record_version) + struct.pack("!H", len(hs)) + hs


def server_hello(cipher=0x1301, selected_version=0x0304) -> bytes:
    body = struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00" + struct.pack("!H", cipher) + b"\x00"
    ext_bytes = ext(43, struct.pack("!H", selected_version))
    body += struct.pack("!H", len(ext_bytes)) + ext_bytes
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tcp(src, dst, sport, dport, flags, t, payload=b""):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = t
    return pkt


def tls_session(client="10.0.0.5", server="93.184.216.34", cport=51000, sport=443, t0=1_700_000_000.0,
                sni="files.example.com", upload=b""):
    """A complete TCP+TLS exchange, closed with FIN/FIN and a trailing ACK."""
    hello = client_hello(extensions=[sni_ext(sni), groups_ext((23, 24, 25)), point_formats_ext((0,))])
    pkts = [
        tcp(client, server, cport, sport, "S", t0),
        tcp(server, client, sport, cport, "SA", t0 + 0.01),
        tcp(client, server, cport, sport, "A", t0 + 0.02),
        tcp(client, server, cport, sport, "PA", t0 + 0.03, hello),
        tcp(server, client, sport, cport, "PA", t0 + 0.05, server_hello()),
    ]
    if upload:
        pkts.append(tcp(client, server, cport, sport, "PA", t0 + 0.10, upload))
    pkts += [
        tcp(client, server, cport, sport, "FA", t0 + 0.20),
        tcp(server, client, sport, cport, "FA", t0 + 0.21),
        tcp(client, server, cport, sport, "A", t0 + 0.22),
    ]
    return pkts


__all__ = [
    "IP", "IPv6", "TCP", "UDP", "ICMP", "Raw",
    "JA3_REFERENCE_STRING", "JA3_REFERENCE_MD5", "REFERENCE_CIPHERS",
    "ext", "sni_ext", "groups_ext", "point_formats_ext", "client_hello", "server_hello", "tcp", "tls_session",
]
