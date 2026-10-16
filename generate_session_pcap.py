"""
Session PCAP Generator
======================
Extracts all recorded network flows and application file activities from the
database, synthesizes authentic Scapy packet captures (complete with TCP 3-way
handshakes, TLS Client/Server Hello handshakes, data frames, and FIN teardowns),
and writes a 100% standard, Wireshark-compatible PCAP file.
"""
import os
import sys
import time
from datetime import timezone

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from scapy.all import IP, TCP, Raw, wrpcap
from scapy.utils import PcapReader
from tests.net_builders import (
    client_hello, server_hello, sni_ext, groups_ext, point_formats_ext, tcp
)
from app import create_app
from core.models import Event, StoredFile
from services.live_collector import validate_pcap_header

def build_session_pcap(output_path: str = "session_traffic.pcap"):
    app = create_app()
    all_packets = []

    with app.app_context():
        # 1. Fetch all network flows from the session
        flows = Event.query.filter(
            Event.event_type.in_(("network_flow", "network_record"))
        ).order_by(Event.event_time.asc()).all()

        # 2. Fetch all file upload events
        uploads = Event.query.filter_by(
            event_type="application_activity"
        ).order_by(Event.event_time.asc()).all()

        print(f"[*] Found {len(flows)} network flows and {len(uploads)} application activities.")

        # --- Reconstruct Packets for Network Flows ---
        for f in flows:
            src_ip = f.src_ip or "192.168.1.50"
            dst_ip = f.dst_ip or "45.33.32.156"
            src_port = f.src_port or 51000
            dst_port = f.dst_port or 443
            total_bytes = f.bytes_transferred or 1500
            pkt_count = max(f.packet_count or 6, 6)
            base_t = f.event_time.replace(tzinfo=timezone.utc).timestamp() if f.event_time else time.time()

            # 3-Way Handshake
            seq = 1000
            ack = 1
            all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "S", base_t))
            all_packets.append(tcp(dst_ip, src_ip, dst_port, src_port, "SA", base_t + 0.005))
            all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "A", base_t + 0.010))

            # TLS Handshake (for HTTPS / port 443 / 8443)
            curr_t = base_t + 0.015
            if dst_port in (443, 8443):
                hello = client_hello(extensions=[
                    sni_ext("cloud-vault.internal" if "192.168" in dst_ip else "secure-egress.external"),
                    groups_ext((23, 24, 25)),
                    point_formats_ext((0,))
                ])
                all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "PA", curr_t, payload=hello))
                curr_t += 0.010
                all_packets.append(tcp(dst_ip, src_ip, dst_port, src_port, "PA", curr_t, payload=server_hello()))
                curr_t += 0.010

            # Data transfer packets (Payload chunks)
            chunk_size = 1420
            remaining_bytes = total_bytes
            data_packets_to_gen = min(pkt_count, 20)  # Representative packet stream
            for i in range(data_packets_to_gen):
                this_chunk = min(remaining_bytes, chunk_size)
                if this_chunk <= 0:
                    this_chunk = 64
                payload_data = b"\x17\x03\x03" + (b"\xaa" * min(this_chunk, 500))  # Encrypted Application Data
                all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "PA", curr_t, payload=payload_data))
                curr_t += 0.002
                remaining_bytes -= this_chunk

            # Teardown (FIN/ACK)
            all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "FA", curr_t))
            all_packets.append(tcp(dst_ip, src_ip, dst_port, src_port, "FA", curr_t + 0.005))
            all_packets.append(tcp(src_ip, dst_ip, src_port, dst_port, "A", curr_t + 0.010))

        # --- Reconstruct Packets for File Upload Operations ---
        for u in uploads:
            client_ip = u.src_ip or "192.168.0.157"
            server_ip = "192.168.0.157"
            cport = 52400 + (u.id % 1000)
            sport = 5000
            u_bytes = u.bytes_transferred or 5000
            u_t = u.event_time.replace(tzinfo=timezone.utc).timestamp() if u.event_time else time.time()

            # HTTP POST /api/v1/files stream
            all_packets.append(tcp(client_ip, server_ip, cport, sport, "S", u_t))
            all_packets.append(tcp(server_ip, client_ip, sport, cport, "SA", u_t + 0.002))
            all_packets.append(tcp(client_ip, server_ip, cport, sport, "A", u_t + 0.004))

            http_header = f"POST /api/v1/files HTTP/1.1\r\nHost: portal.veylix.corp:5000\r\nContent-Length: {u_bytes}\r\n\r\n".encode()
            all_packets.append(tcp(client_ip, server_ip, cport, sport, "PA", u_t + 0.006, payload=http_header))

            # File payload chunks
            p_chunk = b"UPLOAD_FILE_PAYLOAD_CHUNK_DATA_" + (b"X" * 1000)
            all_packets.append(tcp(client_ip, server_ip, cport, sport, "PA", u_t + 0.010, payload=p_chunk))

            # HTTP 201 Response
            http_resp = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"status\":\"stored\"}"
            all_packets.append(tcp(server_ip, client_ip, sport, cport, "PA", u_t + 0.020, payload=http_resp))

            all_packets.append(tcp(client_ip, server_ip, cport, sport, "FA", u_t + 0.030))
            all_packets.append(tcp(server_ip, client_ip, sport, cport, "A", u_t + 0.032))

    # Sort all packets strictly by timestamp
    all_packets.sort(key=lambda p: getattr(p, "time", 0.0))

    print(f"[*] Total synthesized packets: {len(all_packets)}")
    wrpcap(output_path, all_packets)
    print(f"[+] Successfully wrote PCAP file to: {os.path.abspath(output_path)}")
    print(f"[+] File Size: {os.path.getsize(output_path)} bytes")

    # Validate generated PCAP file
    validate_pcap_header(output_path)
    with PcapReader(output_path) as reader:
        validated_count = sum(1 for _ in reader)
    print(f"[+] Validated PCAP structure with PcapReader: {validated_count} packets confirmed readable.")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "session_traffic.pcap"
    build_session_pcap(out_file)
