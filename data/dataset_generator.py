"""
BoT-IoT Dataset Generator and Loader for Encrypted Traffic Insider Threat Detection
Generates realistic BoT-IoT formatted CSV datasets containing both normal baseline traffic
and insider data exfiltration attacks across encrypted channels (TLS 443, SSH 22, DoH 53).
"""
import os
import random
import time
import pandas as pd
import numpy as np


def generate_botiot_datasets(output_dir: str, num_normal: int = 1500, num_attack: int = 600):
    """
    Generates training (Normal baseline) and testing (Normal + Insider Exfiltration attacks) datasets.
    """
    os.makedirs(output_dir, exist_ok=True)
    random.seed(42)
    np.random.seed(42)

    internal_ips = [
        "192.168.1.45", "192.168.1.102", "192.168.1.105", "192.168.1.18",
        "192.168.1.77", "192.168.1.89", "192.168.1.210", "192.168.1.14"
    ]
    benign_external_ips = [
        "142.250.190.46", "13.107.42.14", "151.101.65.140", "172.217.16.206",
        "104.244.42.1", "52.84.12.9"
    ]
    malicious_external_ips = [
        "198.51.100.77", "203.0.113.88", "185.220.101.5", "45.33.32.156", "91.240.118.172"
    ]

    base_time = time.time() - 86400  # 24 hours ago
    normal_rows = []

    # 1. Generate Normal Baseline Traffic
    # Workstation web browsing, API calls, internal DB queries, Slack, Github
    for i in range(num_normal):
        t = base_time + (i * random.uniform(0.05, 0.4))
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(benign_external_ips)
        proto = "tcp"
        sport = random.randint(49152, 65535)
        dport = random.choice([443, 80, 53, 8443])

        # Normal web/TLS packet distribution: varied small ACK/handshakes + medium payloads
        pkts = random.randint(5, 45)
        mean_pkt_size = random.uniform(200.0, 650.0)
        std_pkt_size = random.uniform(50.0, 280.0)
        bytes_total = int(pkts * mean_pkt_size)
        dur = random.uniform(0.1, 4.5)
        rate = pkts / max(dur, 0.01)
        srate = rate * random.uniform(0.4, 0.6)
        drate = rate - srate

        normal_rows.append({
            "pkSeqID": i + 1,
            "stime": t,
            "flgs": "e",
            "proto": proto,
            "saddr": src_ip,
            "sport": sport,
            "daddr": dst_ip,
            "dport": dport,
            "pkts": pkts,
            "bytes": bytes_total,
            "dur": round(dur, 4),
            "mean": round(mean_pkt_size, 2),
            "stddev": round(std_pkt_size, 2),
            "sum": bytes_total,
            "min": max(40, int(mean_pkt_size - std_pkt_size)),
            "max": int(mean_pkt_size + std_pkt_size * 2),
            "spkts": int(pkts * 0.5),
            "dpkts": int(pkts * 0.5),
            "sbytes": int(bytes_total * 0.45),
            "dbytes": int(bytes_total * 0.55),
            "rate": round(rate, 2),
            "srate": round(srate, 2),
            "drate": round(drate, 2),
            "category": "Normal",
            "subcategory": "Normal",
            "attack": 0
        })

    df_normal = pd.DataFrame(normal_rows)
    normal_csv_path = os.path.join(output_dir, "botiot_normal_train.csv")
    df_normal.to_csv(normal_csv_path, index=False)

    # 2. Generate Testing Dataset (Mix of Normal + Insider Exfiltration Attacks)
    test_rows = []
    # Include 400 normal background flows
    test_rows.extend(normal_rows[:400])

    # Insider Attacker: Rogue employee on host 192.168.1.105 (Engineering)
    attacker_ip = "192.168.1.105"
    attacker_ip_2 = "192.168.1.77"

    for j in range(num_attack):
        seq = len(test_rows) + 1
        t = base_time + (num_normal * 0.2) + (j * random.uniform(0.01, 0.08))
        attack_type = random.choice([
            "Bulk_TLS_Exfiltration",
            "OffHours_SFTP_Dump",
            "DoH_Data_Tunneling",
            "Slow_Stegano_Beaconing"
        ])

        if attack_type == "Bulk_TLS_Exfiltration":
            # High speed multi-megabyte encrypted archive upload to foreign IP over 443
            src_ip = attacker_ip
            dst_ip = random.choice(malicious_external_ips)
            proto = "tcp"
            dport = 443
            sport = 55120
            pkts = random.randint(150, 850)
            mean_pkt_size = random.uniform(1350.0, 1490.0) # Near max MTU
            std_pkt_size = random.uniform(5.0, 35.0)       # Extremely uniform high-entropy payload
            bytes_total = int(pkts * mean_pkt_size)
            dur = random.uniform(0.5, 2.0)
            rate = pkts / max(dur, 0.01)
            sbytes = int(bytes_total * 0.96)               # 96% outbound upload
            dbytes = int(bytes_total * 0.04)

        elif attack_type == "OffHours_SFTP_Dump":
            # Off-hours secure shell dump of database files
            src_ip = attacker_ip_2
            dst_ip = "203.0.113.88"
            proto = "tcp"
            dport = 22
            sport = 49200
            pkts = random.randint(200, 600)
            mean_pkt_size = random.uniform(1200.0, 1460.0)
            std_pkt_size = random.uniform(10.0, 40.0)
            bytes_total = int(pkts * mean_pkt_size)
            dur = random.uniform(0.8, 3.0)
            rate = pkts / max(dur, 0.01)
            sbytes = int(bytes_total * 0.94)
            dbytes = int(bytes_total * 0.06)

        elif attack_type == "DoH_Data_Tunneling":
            # Encrypted DNS exfiltration over HTTPS (port 53/443)
            src_ip = attacker_ip
            dst_ip = "185.220.101.5"
            proto = "udp"
            dport = 53
            sport = random.randint(50000, 60000)
            pkts = random.randint(60, 200)
            mean_pkt_size = random.uniform(450.0, 800.0)
            std_pkt_size = random.uniform(15.0, 50.0)
            bytes_total = int(pkts * mean_pkt_size)
            dur = random.uniform(0.2, 1.2)
            rate = pkts / max(dur, 0.01)
            sbytes = int(bytes_total * 0.90)
            dbytes = int(bytes_total * 0.10)

        else: # Slow_Stegano_Beaconing
            src_ip = attacker_ip_2
            dst_ip = "45.33.32.156"
            proto = "tcp"
            dport = 8443
            sport = 51000
            pkts = random.randint(40, 100)
            mean_pkt_size = random.uniform(900.0, 1100.0)
            std_pkt_size = random.uniform(20.0, 60.0)
            bytes_total = int(pkts * mean_pkt_size)
            dur = random.uniform(1.0, 4.0)
            rate = pkts / max(dur, 0.01)
            sbytes = int(bytes_total * 0.88)
            dbytes = int(bytes_total * 0.12)

        srate = rate * (sbytes / max(bytes_total, 1))
        drate = rate - srate

        test_rows.append({
            "pkSeqID": seq,
            "stime": t,
            "flgs": "e",
            "proto": proto,
            "saddr": src_ip,
            "sport": sport,
            "daddr": dst_ip,
            "dport": dport,
            "pkts": pkts,
            "bytes": bytes_total,
            "dur": round(dur, 4),
            "mean": round(mean_pkt_size, 2),
            "stddev": round(std_pkt_size, 2),
            "sum": bytes_total,
            "min": max(40, int(mean_pkt_size - std_pkt_size)),
            "max": int(mean_pkt_size + std_pkt_size * 2),
            "spkts": int(pkts * 0.7),
            "dpkts": int(pkts * 0.3),
            "sbytes": sbytes,
            "dbytes": dbytes,
            "rate": round(rate, 2),
            "srate": round(srate, 2),
            "drate": round(drate, 2),
            "category": "Theft",
            "subcategory": attack_type,
            "attack": 1
        })

    df_test = pd.DataFrame(test_rows)
    # Shuffle test rows slightly to interleave normal and attack
    df_test = df_test.sample(frac=1.0, random_state=42).reset_index(drop=True)
    test_csv_path = os.path.join(output_dir, "botiot_attack_test.csv")
    df_test.to_csv(test_csv_path, index=False)

    print(f"Generated {len(df_normal)} Normal training records -> {normal_csv_path}")
    print(f"Generated {len(df_test)} Testing records ({num_attack} exfiltrations) -> {test_csv_path}")
    return normal_csv_path, test_csv_path


if __name__ == "__main__":
    generate_botiot_datasets(r"d:\invaders 3.0\data")
