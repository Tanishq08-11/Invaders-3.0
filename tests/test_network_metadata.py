"""
Unit tests: packet metadata extraction, TLS handshake metadata (JA3), flow aggregation,
Zeek ssl.log parsing. No database, no model.
"""
import json

import pytest

from net_builders import (
    ICMP, IP, IPv6, JA3_REFERENCE_MD5, JA3_REFERENCE_STRING, Raw, TCP, UDP,
    client_hello, ext, groups_ext, point_formats_ext, server_hello, sni_ext, tcp, tls_session,
)
from services.flow_aggregator import FlowAggregator, canonical_key
from services.network_metadata import classify_direction, extract_packet_metadata
from services.tls_metadata import is_grease, parse_tls_handshake
from services.zeek_tls import parse_ssl_log


# ---------------------------------------------------------------- packet metadata
def test_tcp_metadata_flags_direction_and_no_payload():
    secret = b"TOP-SECRET-PAYLOAD-CONTENT"
    pkt = IP(src="10.1.2.3", dst="8.8.8.8") / TCP(sport=50000, dport=443, flags="PA") / Raw(load=secret)
    pkt.time = 1_700_000_000.5
    meta = extract_packet_metadata(pkt)
    assert meta["protocol"] == "TCP" and meta["src_port"] == 50000 and meta["dst_port"] == 443
    assert meta["tcp_flags"] == "PA"
    assert meta["direction"] == "outbound"
    assert meta["payload_bytes"] == len(secret)
    assert meta["timestamp"] == 1_700_000_000.5
    assert meta["bytes"] == len(pkt)
    assert "TOP-SECRET" not in json.dumps(meta)  # size only, never content


def test_udp_icmp_ipv6_and_non_ip():
    udp = extract_packet_metadata(IP(src="8.8.8.8", dst="192.168.0.9") / UDP(sport=53, dport=5353))
    assert udp["protocol"] == "UDP" and udp["direction"] == "inbound" and udp["tcp_flags"] is None
    icmp = extract_packet_metadata(IP(src="192.168.0.1", dst="192.168.0.2") / ICMP())
    assert icmp["protocol"] == "ICMP" and icmp["src_port"] is None and icmp["direction"] == "internal"
    v6 = extract_packet_metadata(IPv6(src="2001:db8::1", dst="2001:4860::8888") / TCP(sport=1, dport=443))
    assert v6["ip_version"] == 6 and v6["protocol"] == "TCP"
    from scapy.all import ARP, Ether
    assert extract_packet_metadata(Ether() / ARP()) is None


def test_truncated_headers_are_rejected_not_raised():
    raw = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / TCP())[:22]  # IP header + 2 bytes of TCP
    from scapy.all import IP as IPCls
    meta = extract_packet_metadata(IPCls(raw))
    # Scapy may parse a partial TCP layer; either way the extractor must not raise.
    assert meta is None or meta["src_ip"] == "10.0.0.1"


def test_direction_classification():
    assert classify_direction("10.0.0.1", "1.1.1.1") == "outbound"
    assert classify_direction("1.1.1.1", "172.16.0.1") == "inbound"
    assert classify_direction("1.1.1.1", "9.9.9.9") == "external"
    assert classify_direction("not-an-ip", "1.1.1.1") is None


# ---------------------------------------------------------------- TLS metadata
def test_ja3_matches_reference_vector():
    meta = parse_tls_handshake(client_hello())
    assert meta["handshake"] == "client_hello" and meta["complete"] is True
    assert meta["ja3_string"] == JA3_REFERENCE_STRING
    assert meta["ja3"] == JA3_REFERENCE_MD5
    assert meta["sni"] == "files.example.com"


def test_ja3_ignores_grease_values():
    hello = client_hello(
        ciphers=(0x0A0A,) + (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
        extensions=[ext(0x1A1A, b""), sni_ext("a.example"), groups_ext((0x2A2A, 23, 24, 25)), point_formats_ext((0,))],
    )
    meta = parse_tls_handshake(hello)
    assert meta["ja3"] == JA3_REFERENCE_MD5
    assert is_grease(0xFAFA) and not is_grease(0x0A0B)


def test_truncated_client_hello_has_no_fingerprint():
    hello = client_hello()
    meta = parse_tls_handshake(hello[:-6])  # last extension cut off
    assert meta is not None and meta["complete"] is False
    assert "ja3" not in meta  # never guessed from a partial hello
    assert meta["sni"] == "files.example.com"  # earlier, complete extensions still reported


def test_server_hello_negotiated_version_and_non_tls():
    meta = parse_tls_handshake(server_hello(cipher=0x1302, selected_version=0x0304))
    assert meta["negotiated_version"] == "TLS 1.3" and meta["cipher_suite"] == "0x1302"
    assert parse_tls_handshake(b"\x17\x03\x03\x00\x10" + b"x" * 16) is None   # application data
    assert parse_tls_handshake(b"GET / HTTP/1.1\r\n") is None
    assert parse_tls_handshake(b"\x16\x03\x01\x00") is None                   # header cut off


def test_packet_extraction_includes_tls_metadata():
    pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="PA") / Raw(load=client_hello())
    meta = extract_packet_metadata(pkt)
    assert meta["tls"]["sni"] == "files.example.com"
    assert meta["tls"]["ja3"] == JA3_REFERENCE_MD5
    assert meta["tls"]["extraction_source"] == "builtin"


# ---------------------------------------------------------------- flow aggregation
def _metas(pkts):
    return [extract_packet_metadata(p) for p in pkts]


def test_bidirectional_grouping_and_tcp_close():
    agg = FlowAggregator(idle_timeout=30, active_timeout=300)
    emitted, ids = [], set()
    for m in _metas(tls_session(upload=b"x" * 500)):
        fid, done = agg.update(m)
        ids.add(fid)
        emitted += done
    assert len(ids) == 1, "both directions and the trailing ACK belong to one flow"
    assert len(emitted) == 1 and agg.active_flows == 0
    flow = emitted[0]
    d = flow["details"]
    assert flow["src_ip"] == "10.0.0.5" and flow["dst_port"] == 443  # initiator from the bare SYN
    assert d["initiator_inferred"] is False
    assert d["end_reason"] == "tcp_close"
    assert d["fwd_packets"] == 5 and d["bwd_packets"] == 3  # trailing ACK counted as late, not a new flow
    assert d["total_packets"] == 8 == flow["pkts"]
    assert d["fwd_bytes"] + d["bwd_bytes"] == d["total_bytes"]
    assert d["tcp_flags"]["syn"] == 2 and d["tcp_flags"]["fin"] == 2
    assert d["inter_arrival_s"]["min"] is not None and d["packet_size"]["max"] >= d["packet_size"]["min"]
    assert d["tls"]["sni"] == "files.example.com" and d["tls"]["ja3"] == JA3_REFERENCE_MD5
    assert d["tls"]["server_negotiated_version"] == "TLS 1.3"
    assert agg.stats()["late_packets"] == 1


def test_canonical_key_is_direction_independent():
    a = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 1000, "dst_port": 53, "protocol": "UDP"}
    b = {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "src_port": 53, "dst_port": 1000, "protocol": "UDP"}
    assert canonical_key(a) == canonical_key(b)


def test_rst_closes_flow():
    agg = FlowAggregator()
    agg.update(extract_packet_metadata(tcp("10.0.0.1", "1.1.1.1", 4000, 443, "S", 10.0)))
    _, done = agg.update(extract_packet_metadata(tcp("1.1.1.1", "10.0.0.1", 443, 4000, "R", 10.1)))
    assert len(done) == 1 and done[0]["details"]["end_reason"] == "tcp_close"


def test_idle_timeout_and_single_packet_flow_has_no_iat():
    agg = FlowAggregator(idle_timeout=5, active_timeout=300)
    agg.update(extract_packet_metadata(IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1, dport=53)) | {"timestamp": 100.0})
    assert agg.expire(103.0) == []
    done = agg.expire(106.0)
    assert len(done) == 1 and done[0]["details"]["end_reason"] == "idle_timeout"
    assert done[0]["details"]["inter_arrival_s"] == {"min": None, "max": None, "mean": None, "std": None}
    assert done[0]["details"]["tcp_flags"] is None  # UDP: not applicable, not zero


def test_active_timeout_splits_long_flows():
    agg = FlowAggregator(idle_timeout=50, active_timeout=60)
    base = {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "src_port": 5, "dst_port": 443, "protocol": "UDP", "bytes": 100}
    first, _ = agg.update({**base, "timestamp": 0.0})
    for t in range(10, 60, 10):
        agg.update({**base, "timestamp": float(t)})
    second, done = agg.update({**base, "timestamp": 61.0})
    assert len(done) == 1 and done[0]["details"]["end_reason"] == "active_timeout"
    assert first != second


def test_flush_and_eviction_bound_memory():
    agg = FlowAggregator(max_flows=3)
    out = []
    for i in range(5):
        _, done = agg.update({"src_ip": f"10.0.0.{i}", "dst_ip": "1.1.1.1", "src_port": 1, "dst_port": 2,
                              "protocol": "UDP", "bytes": 10, "timestamp": float(i)})
        out += done
    assert agg.active_flows == 3 and len(out) == 2
    assert all(f["details"]["end_reason"] == "evicted" for f in out)
    flushed = agg.flush("collector_stopped")
    assert len(flushed) == 3 and agg.active_flows == 0
    assert {f["details"]["end_reason"] for f in flushed} == {"collector_stopped"}


def test_malformed_metadata_is_rejected():
    agg = FlowAggregator()
    assert agg.update({"src_ip": None, "dst_ip": "1.1.1.1", "timestamp": 1.0}) == (None, [])
    assert agg.update({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}) == (None, [])  # no timestamp
    assert agg.stats()["packets_rejected"] == 2 and agg.active_flows == 0


# ---------------------------------------------------------------- Zeek
def test_zeek_ssl_log_parser(tmp_path):
    log = tmp_path / "ssl.log"
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tserver_name\testablished\tja3\n"
        "1700000000.0\tC1\t10.0.0.5\t51000\t93.184.216.34\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tfiles.example.com\tT\t-\n"
        "#close\t2026-01-01\n",
        encoding="utf-8",
    )
    recs = parse_ssl_log(str(log))
    rec = recs[("10.0.0.5", 51000, "93.184.216.34", 443)]
    assert rec["sni"] == "files.example.com" and rec["version"] == "TLSv13" and rec["established"] is True
    assert "ja3" not in rec  # "-" (unset) is omitted, never filled in
    assert rec["extraction_source"] == "zeek"
