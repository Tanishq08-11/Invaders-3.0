"""
Live Network Collector CLI & Daemon
===================================
Captures network traffic, extracts 5-tuple metadata (zero payload decryption),
and streams it directly into the Person 4 Threat Detection Engine.

Usage:
  python live_collector.py --list-interfaces
  python live_collector.py --interface "Wi-Fi" --filter "ip"
  python live_collector.py --pcap sample.pcap
  python live_collector.py --simulate --rate 5
"""
import sys
import os
import time
import argparse
import json

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from services.live_collector import LiveCollector
from services.event_processor import EventProcessor


def main():
    parser = argparse.ArgumentParser(description="Live Network Metadata Collector — Person 4 Pipeline")
    parser.add_argument("--list-interfaces", action="store_true", help="List all available network interfaces")
    parser.add_argument("--interface", type=str, default=None, help="Name of network interface to sniff on")
    parser.add_argument("--filter", type=str, default="ip", help="BPF packet filter (e.g. 'tcp or udp')")
    parser.add_argument("--pcap", type=str, default=None, help="Path to offline .pcap or .pcapng file to process")
    parser.add_argument("--simulate", action="store_true", help="Run simulated live traffic generator")
    parser.add_argument("--rate", type=float, default=2.0, help="Events per second for simulation (default: 2)")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 = run indefinitely)")

    args = parser.parse_args()
    collector = LiveCollector.get_instance()

    # 1. List interfaces
    if args.list_interfaces:
        ifaces = collector.list_interfaces()
        print(f"\nAvailable Network Interfaces ({len(ifaces)}):")
        print("-" * 50)
        for iface in ifaces:
            print(f"  • {iface}")
        print("-" * 50)
        return

    # 2. Process PCAP file
    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"[Error] PCAP file not found: {args.pcap}", file=sys.stderr)
            sys.exit(1)
        print(f"\n[Collector] Processing PCAP: {args.pcap} ...")
        res = collector.process_pcap_file(args.pcap)
        print(f"[Collector] PCAP Processing Complete:")
        print(json.dumps(res, indent=2))
        return

    # 3. Live or Simulated Sniffing
    print("\n" + "=" * 60)
    print("  Insider Threat Detection — Live Network Collector")
    print("  Extracting: 5-tuple metadata  |  Payload Decryption: ZERO")
    print("=" * 60)

    res = collector.start_live_capture(interface=args.interface, bpf_filter=args.filter, simulate=args.simulate)
    mode_str = "simulated" if args.simulate else ("live-sniffer" if res.get("scapy_live") else "fallback")
    print(f"[Collector] Status:    {res.get('status')}")
    print(f"[Collector] Mode:      {mode_str}")
    print(f"[Collector] Interface: {res.get('interface')}")
    print("\nPress Ctrl+C to stop packet capture...\n")

    start_time = time.time()
    try:
        while True:
            time.sleep(2.0)
            status = collector.get_status()
            print(f"[{time.strftime('%X')}] Captured: {status['packets_captured']} packets | "
                  f"Ingested: {status['events_ingested']} events | "
                  f"Throughput: {status['throughput_pps']:.1f} pkts/s")
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                print(f"[Collector] Reached target duration of {args.duration}s. Stopping.")
                break
    except KeyboardInterrupt:
        print("\n[Collector] Interrupted by user.")
    finally:
        stop_res = collector.stop_capture()
        print(f"[Collector] Capture stopped: {stop_res}")


if __name__ == "__main__":
    main()
