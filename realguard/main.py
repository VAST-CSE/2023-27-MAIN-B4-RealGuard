"""
main.py

RealGuard pipeline orchestrator.

    PacketSniffer -> FeatureExtractor (host features, per device)
    PacketSniffer -> FlowExtractor    (flow features, per connection)

Run from the project root with admin rights:
    python main.py
"""

from core.capture.packet_sniffer import PacketSniffer
from core.features.extractor import FeatureExtractor
from core.features.flow_extractor import FlowExtractor, FLOW_FEATURE_NAMES
from utils.logger import get_logger

logger = get_logger(__name__)

TOP_FLOWS_TO_SHOW = 5


def run_pipeline():
    sniffer = PacketSniffer()
    host_extractor = FeatureExtractor()
    flow_extractor = FlowExtractor()

    sniffer.start()
    logger.info("RealGuard pipeline started.")
    print(f"RealGuard is running ({len(FLOW_FEATURE_NAMES)} flow features per flow). Ctrl+C to stop.\n")

    try:
        while True:
            batch = sniffer.get_batch()

            host_rows = host_extractor.extract(batch)
            flow_rows = flow_extractor.extract(batch)

            print(f"\n=== Window: {len(batch)} packets | {len(host_rows)} devices | {len(flow_rows)} flows ===")

            for row in host_rows:
                print(
                    f"[HOST] {row['src_ip']:<15} | "
                    f"pkt/s: {row['packet_rate']:<6} | "
                    f"ports: {row['unique_dst_ports']:<4} | "
                    f"dst_ips: {row['unique_dst_ips']:<3} | "
                    f"burst: {row['burst_score']:<5} | "
                    f"failed: {row['failed_connections']}"
                )

            busiest = sorted(
                flow_rows,
                key=lambda f: f["tot_fwd_pkts"] + f["tot_bwd_pkts"],
                reverse=True,
            )[:TOP_FLOWS_TO_SHOW]

            for f in busiest:
                print(
                    f"[FLOW] {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} "
                    f"{f['protocol']:<4} | "
                    f"fwd/bwd pkts: {int(f['tot_fwd_pkts'])}/{int(f['tot_bwd_pkts'])} | "
                    f"dur: {f['flow_duration']:.2f}s | "
                    f"bytes/s: {f['flow_byts_s']:.0f} | "
                    f"SYN: {int(f['syn_flag_cnt'])} RST: {int(f['rst_flag_cnt'])}"
                )

    except KeyboardInterrupt:
        print("\nStopping RealGuard...")
        sniffer.stop()
        logger.info("RealGuard pipeline stopped by user.")


if __name__ == "__main__":
    run_pipeline()