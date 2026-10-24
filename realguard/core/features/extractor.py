"""
core/features/extractor.py

Feature Extraction Layer.

Why this exists:
Raw packets tell you almost nothing individually. A single packet is meaningless —
what matters is behavior aggregated over time: how many packets/sec is this device
sending, to how many different ports, in what protocol mix. This module takes a
batch of raw packet dicts (from packet_sniffer.py) and converts them into ONE
feature vector PER SOURCE DEVICE for that time window.

This is the bridge between "raw traffic" and "something a detection engine can
reason about." Every detection engine downstream (rule, statistical, ML) consumes
the output of this module — none of them ever touch a raw packet directly.

Design note on grouping:
A single window's batch contains packets from every active device mixed together.
We group by src_ip first, because "is this behavior weird?" only makes sense
per-device — one device's port scan shouldn't get averaged away by three other
devices' normal traffic in the same window.

Honesty note on "failed connections":
True failed-connection detection requires stateful tracking of full TCP handshakes
(SYN -> SYN-ACK -> ACK) across packets, which is a reasonable future improvement.
For now we approximate using TCP flags: RST flags and standalone SYNs are treated
as failed/rejected connection attempts. This is a fair proxy, not perfect ground
truth -- documented here so nobody mistakes it for exact handshake tracking.
"""

from collections import defaultdict
from datetime import datetime
import yaml
import os

from utils.logger import get_logger

logger = get_logger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "settings.yaml")


class FeatureExtractor:
    """
    Converts a batch of raw packet records into per-source-device feature vectors.

    Usage:
        extractor = FeatureExtractor()
        feature_rows = extractor.extract(batch)   # batch = list of packet dicts
        # feature_rows = list of dicts, one per active src_ip in this window
    """

    def __init__(self):
        with open(_CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
        self.window_seconds = config["network"]["window_seconds"]

    def extract(self, batch: list) -> list:
        """
        Main entry point. Takes a raw packet batch (list of dicts from
        PacketSniffer._packet_to_record) and returns a list of feature
        vectors, one per source IP seen in this window.
        """
        if not batch:
            return []

        grouped = self._group_by_source(batch)

        feature_rows = []
        for src_ip, packets in grouped.items():
            row = self._compute_features(src_ip, packets)
            feature_rows.append(row)

        logger.info(f"Extracted {len(feature_rows)} feature vectors from batch of {len(batch)} packets")
        return feature_rows

    def _group_by_source(self, batch: list) -> dict:
        """Groups raw packet records by source IP."""
        grouped = defaultdict(list)
        for pkt in batch:
            if pkt["src_ip"] is not None:
                grouped[pkt["src_ip"]].append(pkt)
        return grouped

    def _compute_features(self, src_ip: str, packets: list) -> dict:
        """
        Computes the full feature vector for one source device's packets
        within this time window. This is the exact set of numbers that
        get fed into the rule engine, statistical engine, and ML model.
        """
        total_packets = len(packets)
        total_bytes = sum(p["size"] for p in packets)

        dst_ips = set(p["dst_ip"] for p in packets if p["dst_ip"])
        dst_ports = set(p["dst_port"] for p in packets if p["dst_port"] is not None)

        tcp_count = sum(1 for p in packets if p["protocol"] == "TCP")
        udp_count = sum(1 for p in packets if p["protocol"] == "UDP")
        icmp_count = sum(1 for p in packets if p["protocol"] == "ICMP")

        # Failed connection proxy: RST flags or lone SYN (no matching data flow)
        # See module docstring "Honesty note" above.
        failed_connections = sum(
            1 for p in packets
            if p["flags"] and ("R" in p["flags"] or p["flags"] == "S")
        )

        # Burst score: max packets in any 1-second slice within the window,
        # normalized by total packets. High burst_score = traffic arrived in
        # a spike rather than spread evenly -- a common flood/scan signature.
        burst_score = self._compute_burst_score(packets)

        row = {
            "timestamp": datetime.now(),
            "src_ip": src_ip,
            "packet_rate": round(total_packets / self.window_seconds, 2),
            "bytes_per_sec": round(total_bytes / self.window_seconds, 2),
            "avg_packet_size": round(total_bytes / total_packets, 2) if total_packets else 0,
            "unique_dst_ips": len(dst_ips),
            "unique_dst_ports": len(dst_ports),
            "tcp_ratio": round(tcp_count / total_packets, 3) if total_packets else 0,
            "udp_ratio": round(udp_count / total_packets, 3) if total_packets else 0,
            "icmp_ratio": round(icmp_count / total_packets, 3) if total_packets else 0,
            "failed_connections": failed_connections,
            "burst_score": burst_score,
            "total_packets": total_packets,
        }
        return row

    def _compute_burst_score(self, packets: list) -> float:
        """
        Splits the window into 1-second slices and finds the busiest slice.
        Returns busiest_slice_packets / total_packets (0 to 1).
        A value close to 1 means nearly all traffic arrived in a single burst;
        a value close to 1/window_seconds means traffic was evenly spread.
        """
        if not packets:
            return 0.0

        slice_counts = defaultdict(int)
        window_start = min(p["timestamp"] for p in packets)

        for p in packets:
            elapsed = (p["timestamp"] - window_start).total_seconds()
            slice_index = int(elapsed)  # which 1-second slice this packet falls into
            slice_counts[slice_index] += 1

        busiest_slice = max(slice_counts.values())
        return round(busiest_slice / len(packets), 3)


if __name__ == "__main__":
    # Quick manual test using fake packet data (no live capture needed).
    # Run this directly to sanity-check feature computation before wiring
    # it to live capture: python -m core.features.extractor
    from datetime import timedelta

    now = datetime.now()
    fake_batch = [
        {"timestamp": now, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "protocol": "TCP", "dst_port": 22, "size": 60, "flags": "S"},
        {"timestamp": now + timedelta(seconds=1), "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2",
         "protocol": "TCP", "dst_port": 23, "size": 60, "flags": "S"},
        {"timestamp": now + timedelta(seconds=1), "src_ip": "192.168.1.10", "dst_ip": "10.0.0.3",
         "protocol": "TCP", "dst_port": 80, "size": 500, "flags": "A"},
        {"timestamp": now + timedelta(seconds=4), "src_ip": "192.168.1.20", "dst_ip": "10.0.0.1",
         "protocol": "UDP", "dst_port": 53, "size": 80, "flags": None},
    ]

    extractor = FeatureExtractor()
    rows = extractor.extract(fake_batch)
    for row in rows:
        print(row)