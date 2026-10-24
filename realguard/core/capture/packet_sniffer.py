"""
core/capture/packet_sniffer.py

Packet Capture Layer (v2).

Changes from v1:
    Each packet record now also carries src_port, header_len, payload_len and
    tcp_window. The flow extractor needs these to compute CICFlowMeter-style
    features. All v1 fields are unchanged, so the host extractor still works.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import queue
import yaml
import os

from utils.logger import get_logger

logger = get_logger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "settings.yaml")


class PacketSniffer:
    """
    Captures live packets and emits them in timed batches via a queue.

    Usage:
        sniffer = PacketSniffer()
        sniffer.start()
        batch = sniffer.get_batch()
    """

    def __init__(self):
        with open(_CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)

        net_cfg = config["network"]
        self.interface = net_cfg["interface"]
        self.capture_filter = net_cfg["capture_filter"]
        self.window_seconds = net_cfg["window_seconds"]

        self._current_batch = []
        self._batch_queue = queue.Queue()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def _packet_to_record(self, pkt) -> dict:
        record = {
            "timestamp": datetime.now(),
            "size": len(pkt),
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "header_len": 0,
            "payload_len": 0,
            "tcp_window": 0,
        }

        if IP in pkt:
            ip = pkt[IP]
            record["src_ip"] = ip.src
            record["dst_ip"] = ip.dst
            ip_hdr = (ip.ihl or 5) * 4

            if TCP in pkt:
                tcp = pkt[TCP]
                tcp_hdr = (tcp.dataofs or 5) * 4
                record["protocol"] = "TCP"
                record["src_port"] = tcp.sport
                record["dst_port"] = tcp.dport
                record["flags"] = str(tcp.flags)
                record["header_len"] = ip_hdr + tcp_hdr
                record["payload_len"] = max(len(ip) - ip_hdr - tcp_hdr, 0)
                record["tcp_window"] = int(tcp.window)
            elif UDP in pkt:
                record["protocol"] = "UDP"
                record["src_port"] = pkt[UDP].sport
                record["dst_port"] = pkt[UDP].dport
                record["header_len"] = ip_hdr + 8
                record["payload_len"] = max(len(ip) - ip_hdr - 8, 0)
            elif ICMP in pkt:
                record["protocol"] = "ICMP"
                record["header_len"] = ip_hdr + 8
                record["payload_len"] = max(len(ip) - ip_hdr - 8, 0)

        return record

    def _on_packet(self, pkt):
        record = self._packet_to_record(pkt)
        with self._lock:
            self._current_batch.append(record)

    def _flush_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(self.window_seconds)
            with self._lock:
                if self._current_batch:
                    self._batch_queue.put(self._current_batch)
                    logger.info(f"Flushed batch of {len(self._current_batch)} packets")
                    self._current_batch = []

    def start(self):
        logger.info(f"Starting capture on interface={self.interface} filter='{self.capture_filter}'")

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

        self._sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            ),
            daemon=True,
        )
        self._sniff_thread.start()

    def get_batch(self, timeout=None):
        return self._batch_queue.get(timeout=timeout)

    def stop(self):
        logger.info("Stopping capture...")
        self._stop_event.set()


if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start()
    print("Capturing... press Ctrl+C to stop.")
    try:
        while True:
            batch = sniffer.get_batch()
            print(f"Got batch of {len(batch)} packets at {datetime.now()}")
    except KeyboardInterrupt:
        sniffer.stop()