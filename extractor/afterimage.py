"""
AfterImage Feature Extractor for Encrypted Network Traffic
Based on the Kitsune network intrusion detection framework (NDSS 2018).

Extracts 100 damped statistical features from encrypted packet headers (IP, ports, length, timestamp)
WITHOUT decrypting payloads, maintaining privacy and security.
"""
from typing import List, Dict, Optional, Tuple, Any
import numpy as np
from extractor.inc_stat import IncStat1D, IncStat2D


class AfterImage:
    """
    Kitsune AfterImage feature extractor.
    Maintains damped statistical representations across multiple channels and lambdas.
    """
    def __init__(self, lambdas: Optional[List[float]] = None):
        if lambdas is None:
            self.lambdas = [5.0, 3.0, 1.0, 0.1, 0.01]
        else:
            self.lambdas = sorted(lambdas, reverse=True)

        self.num_lambdas = len(self.lambdas)

        # Hash tables for tracking entity statistics across lambdas
        # Channel 1: Host-level (src_ip)
        self.ht_host: Dict[str, List[IncStat1D]] = {}
        # Channel 2: Channel-level (src_ip -> dst_ip)
        self.ht_channel: Dict[str, List[IncStat1D]] = {}
        # Channel 3: Socket-level (src_ip : src_port)
        self.ht_socket: Dict[str, List[IncStat1D]] = {}
        # Channel 4: Conversation-level (src_ip:src_port -> dst_ip:dst_port)
        self.ht_conv: Dict[str, List[IncStat1D]] = {}
        # Channel 5: 2D Jitter/Size correlation for host (src_ip)
        self.ht_jitter_size: Dict[str, List[IncStat2D]] = {}

        # Last seen timestamp per host to calculate packet inter-arrival jitter
        self.last_host_ts: Dict[str, float] = {}

        # Cached feature names
        self.feature_names = self._build_feature_names()

    def _build_feature_names(self) -> List[str]:
        names = []
        # Host stats across lambdas: weight, mean, std (3 * num_lambdas = 15)
        for l in self.lambdas:
            names.extend([
                f"host_pkt_rate_L{l}",
                f"host_pkt_size_mean_L{l}",
                f"host_pkt_size_std_L{l}"
            ])

        # Channel stats (src->dst): weight, mean, std (3 * num_lambdas = 15)
        for l in self.lambdas:
            names.extend([
                f"channel_flow_rate_L{l}",
                f"channel_flow_mean_L{l}",
                f"channel_flow_std_L{l}"
            ])

        # Socket stats (src:port): weight, mean, std (3 * num_lambdas = 15)
        for l in self.lambdas:
            names.extend([
                f"socket_burst_rate_L{l}",
                f"socket_pkt_mean_L{l}",
                f"socket_pkt_std_L{l}"
            ])

        # Conversation stats (src:port -> dst:port): weight, mean, std (3 * num_lambdas = 15)
        for l in self.lambdas:
            names.extend([
                f"conv_stream_rate_L{l}",
                f"conv_stream_mean_L{l}",
                f"conv_stream_std_L{l}"
            ])

        # 2D Jitter-Size stats: covariance, correlation (2 * num_lambdas = 10)
        for l in self.lambdas:
            names.extend([
                f"jitter_size_cov_L{l}",
                f"jitter_size_corr_L{l}"
            ])

        # Derived exfiltration ratios and dynamics across lambdas (6 * num_lambdas = 30)
        for l in self.lambdas:
            names.extend([
                f"channel_to_host_ratio_L{l}",
                f"socket_to_host_ratio_L{l}",
                f"conv_to_channel_ratio_L{l}",
                f"burst_velocity_L{l}",
                f"packet_size_entropy_proxy_L{l}",
                f"flow_asymmetry_metric_L{l}"
            ])

        # Total = 15 + 15 + 15 + 15 + 10 + 30 = 100 features
        return names

    def get_feature_names(self) -> List[str]:
        return self.feature_names

    def get_feature_dimension(self) -> int:
        return len(self.feature_names)

    def _get_or_create_1d(self, table: Dict[str, List[IncStat1D]], key: str) -> List[IncStat1D]:
        if key not in table:
            table[key] = [IncStat1D(l) for l in self.lambdas]
        return table[key]

    def _get_or_create_2d(self, table: Dict[str, List[IncStat2D]], key: str) -> List[IncStat2D]:
        if key not in table:
            table[key] = [IncStat2D(l) for l in self.lambdas]
        return table[key]

    def update_and_extract(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: float
    ) -> np.ndarray:
        """
        Updates internal damped statistics and extracts the 100-dimensional AfterImage feature vector.
        Operates strictly on encrypted packet header metadata.
        """
        key_host = src_ip
        key_channel = f"{src_ip}->{dst_ip}"
        key_socket = f"{src_ip}:{src_port}"
        key_conv = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

        # Calculate inter-arrival jitter
        last_ts = self.last_host_ts.get(src_ip, timestamp)
        dt = max(1e-6, timestamp - last_ts)
        self.last_host_ts[src_ip] = timestamp

        stats_host = self._get_or_create_1d(self.ht_host, key_host)
        stats_channel = self._get_or_create_1d(self.ht_channel, key_channel)
        stats_socket = self._get_or_create_1d(self.ht_socket, key_socket)
        stats_conv = self._get_or_create_1d(self.ht_conv, key_conv)
        stats_jitter = self._get_or_create_2d(self.ht_jitter_size, key_host)

        features = []

        # 1. Host Stats (15)
        for stat in stats_host:
            stat.update(length, timestamp)
            features.extend([stat.weight, stat.mean, stat.std])

        # 2. Channel Stats (15)
        for stat in stats_channel:
            stat.update(length, timestamp)
            features.extend([stat.weight, stat.mean, stat.std])

        # 3. Socket Stats (15)
        for stat in stats_socket:
            stat.update(length, timestamp)
            features.extend([stat.weight, stat.mean, stat.std])

        # 4. Conversation Stats (15)
        for stat in stats_conv:
            stat.update(length, timestamp)
            features.extend([stat.weight, stat.mean, stat.std])

        # 5. Jitter vs Size 2D Stats (10)
        for stat in stats_jitter:
            stat.update(dt, length, timestamp)
            features.extend([stat.covariance, stat.correlation])

        # 6. Derived Exfiltration Indicators across lambdas (30)
        for idx in range(self.num_lambdas):
            w_host = max(1e-5, stats_host[idx].weight)
            w_chan = stats_channel[idx].weight
            w_sock = stats_socket[idx].weight
            w_conv = stats_conv[idx].weight
            std_host = stats_host[idx].std
            mean_host = max(1.0, stats_host[idx].mean)

            chan_host_ratio = w_chan / w_host
            sock_host_ratio = w_sock / w_host
            conv_chan_ratio = w_conv / max(1e-5, w_chan)
            burst_velocity = w_conv * (1.0 / dt if dt > 0 else 1.0)
            entropy_proxy = std_host / mean_host
            # Asymmetry indicator: encrypted bulk upload check
            port_weight = 1.5 if dst_port in [443, 8443, 22, 2222] else 1.0
            asymmetry = (length / mean_host) * port_weight

            features.extend([
                chan_host_ratio,
                sock_host_ratio,
                conv_chan_ratio,
                burst_velocity,
                entropy_proxy,
                asymmetry
            ])

        vec = np.array(features, dtype=np.float32)
        # Clean any potential NaN / Inf values
        vec = np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)
        return vec

    def extract_from_flow(self, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from a dictionary representation of a packet or flow.
        """
        ts = float(flow_dict.get("timestamp", flow_dict.get("stime", 0.0)))
        src_ip = str(flow_dict.get("src_ip", flow_dict.get("saddr", "192.168.1.100")))
        dst_ip = str(flow_dict.get("dst_ip", flow_dict.get("daddr", "10.0.0.1")))
        src_port = int(flow_dict.get("src_port", flow_dict.get("sport", 49152)))
        dst_port = int(flow_dict.get("dst_port", flow_dict.get("dport", 443)))
        proto = str(flow_dict.get("protocol", flow_dict.get("proto", "tcp"))).upper()
        length = float(flow_dict.get("length", flow_dict.get("bytes", 500.0)))

        return self.update_and_extract(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=length
        )

    def reset(self):
        """Reset all state tables."""
        self.ht_host.clear()
        self.ht_channel.clear()
        self.ht_socket.clear()
        self.ht_conv.clear()
        self.ht_jitter_size.clear()
        self.last_host_ts.clear()
