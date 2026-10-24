"""
core/features/flow_extractor.py

Flow-Level Feature Extraction (Level 1).

Groups the packets of one capture window into bidirectional flows
(5-tuple: IP/port pairs + protocol) and computes 54 CICFlowMeter-style
features per flow. These mirror the CIC-IDS2017 feature set, so a model
trained on that dataset can later be applied to live traffic.

Forward direction = direction of the first packet seen in the flow.

Known limitation: flows are computed per capture window, so a flow that lasts
longer than one window is reported as separate partial flows. Stateful
cross-window flow tracking is a possible future refinement.
"""

import math
from collections import defaultdict

from utils.logger import get_logger

logger = get_logger(__name__)

FLOW_FEATURE_NAMES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags",
    "fwd_header_len", "bwd_header_len",
    "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "init_fwd_win_byts", "init_bwd_win_byts",
    "fwd_act_data_pkts", "fwd_seg_size_min",
]


def _stats(values):
    """Returns (total, mean, std, max, min). All zeros for an empty list."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    n = len(values)
    total = float(sum(values))
    mean = total / n
    var = sum((v - mean) ** 2 for v in values) / n
    return total, mean, math.sqrt(var), float(max(values)), float(min(values))


def _iats(times):
    """Inter-arrival times between consecutive timestamps (seconds)."""
    return [times[i] - times[i - 1] for i in range(1, len(times))]


class FlowExtractor:
    """
    Converts a batch of packet records into per-flow feature rows.

    Usage:
        fe = FlowExtractor()
        flows = fe.extract(batch)   # list of dicts: identity fields + 54 features
    """

    def extract(self, batch: list) -> list:
        if not batch:
            return []

        flows = defaultdict(list)
        for pkt in batch:
            if pkt.get("src_ip") is None or pkt.get("protocol") is None:
                continue
            flows[self._flow_key(pkt)].append(pkt)

        rows = [self._compute_flow(pkts) for pkts in flows.values()]
        logger.info(f"Extracted {len(rows)} flows from batch of {len(batch)} packets")
        return rows

    @staticmethod
    def _flow_key(pkt):
        a = (pkt["src_ip"], pkt.get("src_port") or 0)
        b = (pkt["dst_ip"], pkt.get("dst_port") or 0)
        return (min(a, b), max(a, b), pkt["protocol"])

    def _compute_flow(self, pkts: list) -> dict:
        pkts = sorted(pkts, key=lambda p: p["timestamp"])
        first = pkts[0]
        fwd_src = (first["src_ip"], first.get("src_port") or 0)

        fwd, bwd = [], []
        for p in pkts:
            if (p["src_ip"], p.get("src_port") or 0) == fwd_src:
                fwd.append(p)
            else:
                bwd.append(p)

        ts = lambda lst: [p["timestamp"].timestamp() for p in lst]
        all_t, fwd_t, bwd_t = ts(pkts), ts(fwd), ts(bwd)

        duration = max(all_t[-1] - all_t[0], 0.0)
        dur_div = duration if duration > 0 else 1.0

        fwd_len = [p.get("payload_len", 0) for p in fwd]
        bwd_len = [p.get("payload_len", 0) for p in bwd]
        all_len = fwd_len + bwd_len

        _, f_mean, f_std, f_max, f_min = _stats(fwd_len)
        _, b_mean, b_std, b_max, b_min = _stats(bwd_len)
        _, a_mean, a_std, a_max, a_min = _stats(all_len)

        _, fi_mean, fi_std, fi_max, fi_min = _stats(_iats(all_t))
        f_tot, fw_mean, fw_std, fw_max, fw_min = _stats(_iats(fwd_t))
        b_tot, bw_mean, bw_std, bw_max, bw_min = _stats(_iats(bwd_t))

        def flag_count(lst, ch):
            return sum(1 for p in lst if p.get("flags") and ch in p["flags"])

        def flag_total(ch):
            return flag_count(pkts, ch)

        total_bytes = sum(p["size"] for p in pkts)
        total_fwd_bytes = float(sum(fwd_len))
        total_bwd_bytes = float(sum(bwd_len))

        fwd_data_pkts = sum(1 for p in fwd if p.get("payload_len", 0) > 0)
        fwd_hdrs = [p.get("header_len", 0) for p in fwd]

        features = {
            "flow_duration": duration,
            "tot_fwd_pkts": len(fwd),
            "tot_bwd_pkts": len(bwd),
            "totlen_fwd_pkts": total_fwd_bytes,
            "totlen_bwd_pkts": total_bwd_bytes,
            "fwd_pkt_len_max": f_max, "fwd_pkt_len_min": f_min,
            "fwd_pkt_len_mean": f_mean, "fwd_pkt_len_std": f_std,
            "bwd_pkt_len_max": b_max, "bwd_pkt_len_min": b_min,
            "bwd_pkt_len_mean": b_mean, "bwd_pkt_len_std": b_std,
            "flow_byts_s": total_bytes / dur_div,
            "flow_pkts_s": len(pkts) / dur_div,
            "flow_iat_mean": fi_mean, "flow_iat_std": fi_std,
            "flow_iat_max": fi_max, "flow_iat_min": fi_min,
            "fwd_iat_tot": f_tot, "fwd_iat_mean": fw_mean, "fwd_iat_std": fw_std,
            "fwd_iat_max": fw_max, "fwd_iat_min": fw_min,
            "bwd_iat_tot": b_tot, "bwd_iat_mean": bw_mean, "bwd_iat_std": bw_std,
            "bwd_iat_max": bw_max, "bwd_iat_min": bw_min,
            "fwd_psh_flags": flag_count(fwd, "P"),
            "bwd_psh_flags": flag_count(bwd, "P"),
            "fwd_header_len": sum(fwd_hdrs),
            "bwd_header_len": sum(p.get("header_len", 0) for p in bwd),
            "fwd_pkts_s": len(fwd) / dur_div,
            "bwd_pkts_s": len(bwd) / dur_div,
            "pkt_len_min": a_min, "pkt_len_max": a_max,
            "pkt_len_mean": a_mean, "pkt_len_std": a_std, "pkt_len_var": a_std ** 2,
            "fin_flag_cnt": flag_total("F"),
            "syn_flag_cnt": flag_total("S"),
            "rst_flag_cnt": flag_total("R"),
            "psh_flag_cnt": flag_total("P"),
            "ack_flag_cnt": flag_total("A"),
            "urg_flag_cnt": flag_total("U"),
            "down_up_ratio": (len(bwd) / len(fwd)) if fwd else 0.0,
            "pkt_size_avg": total_bytes / len(pkts),
            "fwd_seg_size_avg": f_mean,
            "bwd_seg_size_avg": b_mean,
            "init_fwd_win_byts": fwd[0].get("tcp_window", 0) if fwd else 0,
            "init_bwd_win_byts": bwd[0].get("tcp_window", 0) if bwd else 0,
            "fwd_act_data_pkts": fwd_data_pkts,
            "fwd_seg_size_min": min(fwd_hdrs) if fwd_hdrs else 0,
        }

        row = {
            "timestamp": first["timestamp"],
            "src_ip": first["src_ip"],
            "dst_ip": first["dst_ip"],
            "src_port": first.get("src_port") or 0,
            "dst_port": first.get("dst_port") or 0,
            "protocol": first["protocol"],
        }
        row.update({k: round(float(v), 6) for k, v in features.items()})
        return row


if __name__ == "__main__":
    # Self-test with fake packets: python -m core.features.flow_extractor
    from datetime import datetime, timedelta

    now = datetime.now()

    def pkt(dt, s, sp, d, dp, flags, payload, win=64240):
        return {
            "timestamp": now + timedelta(seconds=dt), "size": payload + 54,
            "src_ip": s, "dst_ip": d, "protocol": "TCP",
            "src_port": sp, "dst_port": dp, "flags": flags,
            "header_len": 40, "payload_len": payload, "tcp_window": win,
        }

    batch = [
        pkt(0.0, "192.168.1.10", 50000, "10.0.0.5", 80, "S", 0),
        pkt(0.1, "10.0.0.5", 80, "192.168.1.10", 50000, "SA", 0, 29200),
        pkt(0.2, "192.168.1.10", 50000, "10.0.0.5", 80, "A", 0),
        pkt(0.3, "192.168.1.10", 50000, "10.0.0.5", 80, "PA", 500),
        pkt(0.5, "10.0.0.5", 80, "192.168.1.10", 50000, "PA", 1200, 29200),
        pkt(1.0, "192.168.1.10", 50000, "10.0.0.5", 80, "FA", 0),
        pkt(0.0, "192.168.1.20", 40000, "10.0.0.6", 22, "S", 0),
    ]

    rows = FlowExtractor().extract(batch)
    print(f"Feature count per flow: {len(FLOW_FEATURE_NAMES)}")
    for r in rows:
        print(f"\nFlow {r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} ({r['protocol']})")
        for name in FLOW_FEATURE_NAMES:
            print(f"  {name:<20} {r[name]}")