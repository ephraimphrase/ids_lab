"""
ids_capture/extract_flows.py
=============================
Convert raw pcap files into a labelled, ML-ready flow CSV (Phase 7).

Extracts per-connection flow features using tshark's -z conv,tcp and
frame-by-frame field extraction, computing the statistical features
used by CICIDS2017 / CICFlowMeter so the resulting dataset is directly
comparable to that benchmark.

Features extracted per flow (5-tuple key: src_ip, dst_ip, src_port, dst_port, protocol):
  - Duration (seconds)
  - Packet count (fwd + bwd)
  - Byte count (fwd + bwd)
  - Mean / std / max / min inter-arrival time (IAT)
  - Packets per second
  - Bytes per second
  - SYN / ACK / RST / FIN / PSH / URG flag counts
  - Header length stats
  - Window size mean

Usage:
    from ids_capture.extract_flows import FlowExtractor
    extractor = FlowExtractor(
        pcap_path="~/captures/PortScan_20260623_140200.pcap",
        output_csv="~/captures/PortScan_flows.csv",
    )
    df = extractor.extract()
    print(df.head())
"""

from __future__ import annotations

import shutil
import statistics
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ip_to_int_tuple(ip: str) -> tuple[int, ...]:
    """Convert a dotted-decimal IP string to a tuple of ints for correct
    numeric comparison.  Falls back to (0,0,0,0) for non-IP strings."""
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Packet record (per-frame data from tshark)
# ---------------------------------------------------------------------------

@dataclass
class _Pkt:
    ts: float           # absolute epoch timestamp
    src: str
    dst: str
    sport: int
    dport: int
    proto: str          # "TCP" | "UDP" | "ICMP" | other
    length: int         # IP total length
    ip_hdr_len: int
    tcp_flags: int      # raw flags byte (0 if not TCP)
    tcp_win: int        # TCP window size


# ---------------------------------------------------------------------------
# Flow record
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # accumulated per-packet lists
    _timestamps: list[float] = field(default_factory=list, repr=False)
    _lengths: list[int] = field(default_factory=list, repr=False)
    _tcp_flags: list[int] = field(default_factory=list, repr=False)
    _tcp_wins: list[int] = field(default_factory=list, repr=False)
    _ip_hdr_lens: list[int] = field(default_factory=list, repr=False)

    def add(self, pkt: _Pkt) -> None:
        self._timestamps.append(pkt.ts)
        self._lengths.append(pkt.length)
        self._tcp_flags.append(pkt.tcp_flags)
        self._tcp_wins.append(pkt.tcp_win)
        self._ip_hdr_lens.append(pkt.ip_hdr_len)

    def to_dict(self) -> dict:
        """Compute all flow-level features and return as a flat dict."""
        if not self._timestamps:
            # Defensive: a FlowRecord should always have at least one packet,
            # but guard against accidental empty construction.
            raise ValueError(f"FlowRecord for {self.src_ip}:{self.src_port} has no packets.")

        ts = sorted(self._timestamps)
        pkt_count = len(ts)

        # Duration
        duration = (ts[-1] - ts[0]) if pkt_count > 1 else 0.0

        # Byte stats
        total_bytes = sum(self._lengths)
        mean_pkt_len = total_bytes / pkt_count if pkt_count else 0.0

        # Inter-arrival times
        iats = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
        if iats:
            mean_iat = statistics.mean(iats)
            std_iat = statistics.stdev(iats) if len(iats) > 1 else 0.0
            max_iat = max(iats)
            min_iat = min(iats)
        else:
            mean_iat = std_iat = max_iat = min_iat = 0.0

        # Rates
        pps = pkt_count / duration if duration > 0 else float(pkt_count)
        bps = total_bytes / duration if duration > 0 else float(total_bytes)

        # TCP flags (bit positions: FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20)
        syn_count = sum(1 for f in self._tcp_flags if f & 0x02)
        ack_count = sum(1 for f in self._tcp_flags if f & 0x10)
        rst_count = sum(1 for f in self._tcp_flags if f & 0x04)
        fin_count = sum(1 for f in self._tcp_flags if f & 0x01)
        psh_count = sum(1 for f in self._tcp_flags if f & 0x08)
        urg_count = sum(1 for f in self._tcp_flags if f & 0x20)

        # Header lengths
        mean_hdr = statistics.mean(self._ip_hdr_lens) if self._ip_hdr_lens else 0.0

        # Window size
        wins = [w for w in self._tcp_wins if w > 0]
        mean_win = statistics.mean(wins) if wins else 0.0

        # Timestamp of first packet (ISO-8601, UTC) — used for window-based labelling
        first_ts = datetime.fromtimestamp(ts[0], tz=timezone.utc).isoformat()

        return {
            "timestamp": first_ts,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": round(duration, 6),
            "pkt_count": pkt_count,
            "total_bytes": total_bytes,
            "mean_pkt_len": round(mean_pkt_len, 2),
            "mean_iat": round(mean_iat, 6),
            "std_iat": round(std_iat, 6),
            "max_iat": round(max_iat, 6),
            "min_iat": round(min_iat, 6),
            "pps": round(pps, 4),
            "bps": round(bps, 4),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "psh_count": psh_count,
            "urg_count": urg_count,
            "mean_header_len": round(mean_hdr, 2),
            "mean_win_size": round(mean_win, 2),
            "syn_ratio": round(syn_count / pkt_count, 4) if pkt_count else 0.0,
            "ack_ratio": round(ack_count / pkt_count, 4) if pkt_count else 0.0,
        }


# ---------------------------------------------------------------------------
# FlowExtractor
# ---------------------------------------------------------------------------

class FlowExtractor:
    """
    Read a pcap, extract per-packet fields with tshark, aggregate into flows,
    and write a labelled CSV.

    Parameters
    ----------
    pcap_path : str | Path
        Input pcap file.
    output_csv : str | Path
        Where to write the flow CSV.  Parent directories are created.
    flow_timeout : float
        Seconds of inactivity before a flow is considered closed and a new
        flow on the same 5-tuple starts.  Default: 120 s (matches common IDS
        tool defaults).
    bidirectional : bool
        If True (default), treat (A→B) and (B→A) as the same flow
        (keyed by sorted tuple).  This matches CICFlowMeter behaviour.
    """

    # tshark fields to extract per frame
    _FIELDS = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "ip.proto",
        "ip.len",
        "ip.hdr_len",
        "tcp.flags",
        "tcp.window_size_value",
    ]

    def __init__(
        self,
        pcap_path: str | Path,
        output_csv: str | Path,
        flow_timeout: float = 120.0,
        bidirectional: bool = True,
    ):
        self.pcap = Path(pcap_path).expanduser().resolve()
        self.output_csv = Path(output_csv).expanduser().resolve()
        self.flow_timeout = flow_timeout
        self.bidirectional = bidirectional
        self._tshark = shutil.which("tshark")
        if not self._tshark:
            raise RuntimeError("tshark not found. Install with: sudo apt install tshark")

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def extract(self) -> pd.DataFrame:
        """
        Run full extraction pipeline:
          1. Read packets from pcap via tshark
          2. Aggregate into flows
          3. Compute features
          4. Write CSV
          5. Return DataFrame
        """
        print(f"[extract] Reading packets from: {self.pcap}", flush=True)
        packets = self._read_packets()
        print(f"[extract] Parsed {len(packets):,} packets", flush=True)

        flows = self._aggregate_flows(packets)
        print(f"[extract] Aggregated into {len(flows):,} flows", flush=True)

        records = [f.to_dict() for f in flows.values()]
        df = pd.DataFrame(records)

        self.output_csv.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(self.output_csv, index=False)
        print(f"[extract] Flow CSV written: {self.output_csv} ({len(df)} rows)", flush=True)
        return df

    # ------------------------------------------------------------------
    # Private: packet reading
    # ------------------------------------------------------------------

    def _read_packets(self) -> list[_Pkt]:
        """Use tshark -T fields to extract per-frame data."""
        field_args = []
        for f in self._FIELDS:
            field_args += ["-e", f]

        cmd = [
            self._tshark,
            "-r", str(self.pcap),
            "-n",                       # no name resolution
            "-T", "fields",
            "-E", "separator=\t",       # tab is safe; pipe can appear in URIs/values
            "-E", "header=n",
        ] + field_args

        try:
            raw = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True, timeout=600
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed: {e}") from e

        packets = []
        for line in raw.splitlines():
            pkt = self._parse_line(line)
            if pkt:
                packets.append(pkt)
        return packets

    def _parse_line(self, line: str) -> Optional[_Pkt]:
        """Parse one tshark fields output line into a _Pkt."""
        parts = line.split("\t")
        if len(parts) < 12:
            return None

        def safe_float(s: str, default: float = 0.0) -> float:
            try:
                return float(s.strip())
            except (ValueError, AttributeError):
                return default

        def safe_int(s: str, default: int = 0, base: int = 10) -> int:
            try:
                return int(s.strip(), base) if s.strip() else default
            except (ValueError, AttributeError):
                return default

        ts = safe_float(parts[0])
        if ts == 0.0:
            return None

        src_ip = parts[1].strip() or "0.0.0.0"
        dst_ip = parts[2].strip() or "0.0.0.0"

        # Determine transport layer
        tcp_sport = safe_int(parts[3])
        tcp_dport = safe_int(parts[4])
        udp_sport = safe_int(parts[5])
        udp_dport = safe_int(parts[6])

        proto_num = safe_int(parts[7])
        # Skip non-IP frames (ARP, STP, etc.): proto_num == 0 means tshark
        # found no ip.proto field — these would produce "0.0.0.0" flows that
        # pollute the dataset with meaningless records.
        if proto_num == 0:
            return None
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto = proto_map.get(proto_num, f"PROTO_{proto_num}")

        if proto == "TCP":
            sport, dport = tcp_sport, tcp_dport
        elif proto == "UDP":
            sport, dport = udp_sport, udp_dport
        else:
            sport, dport = 0, 0

        ip_len = safe_int(parts[8])
        # tshark's ip.hdr_len field is already in bytes (it multiplies the
        # 4-bit IHL field by 4 internally before presenting it).  Do NOT
        # multiply again or every header appears to be 80 bytes instead of 20.
        ip_hdr = safe_int(parts[9])
        tcp_flags_hex = parts[10].strip()
        tcp_flags = safe_int(tcp_flags_hex, 0, 16)
        tcp_win = safe_int(parts[11])

        return _Pkt(
            ts=ts,
            src=src_ip,
            dst=dst_ip,
            sport=sport,
            dport=dport,
            proto=proto,
            length=ip_len,
            ip_hdr_len=ip_hdr,
            tcp_flags=tcp_flags,
            tcp_win=tcp_win,
        )

    # ------------------------------------------------------------------
    # Private: flow aggregation
    # ------------------------------------------------------------------

    def _flow_key(self, pkt: _Pkt) -> tuple:
        """5-tuple key; for bidirectional mode, always put the numerically
        smaller (IP, port) pair first so A→B and B→A map to the same key.
        Uses _ip_to_int_tuple (module-level) for correct numeric IP ordering."""
        if self.bidirectional:
            src_key = (_ip_to_int_tuple(pkt.src), pkt.sport)
            dst_key = (_ip_to_int_tuple(pkt.dst), pkt.dport)
            if src_key > dst_key:
                return (pkt.dst, pkt.src, pkt.dport, pkt.sport, pkt.proto)
        return (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto)

    def _aggregate_flows(self, packets: list[_Pkt]) -> dict[tuple, FlowRecord]:
        """Aggregate packets into flows with timeout splitting."""
        # Sort by timestamp first (pcap should already be ordered, but be safe)
        packets.sort(key=lambda p: p.ts)

        flows: dict[tuple, FlowRecord] = {}
        # Track last-seen time per *active* flow key (not base_key) for timeout
        last_seen: dict[tuple, float] = {}
        # Map base_key -> current active key so we can look up the right flow
        active_key: dict[tuple, tuple] = {}
        # Counter to make unique keys after timeout splits
        split_counts: dict[tuple, int] = defaultdict(int)

        for pkt in packets:
            base_key = self._flow_key(pkt)
            cur_key = active_key.get(base_key, base_key)

            # Check for flow timeout on the *current* active key
            if cur_key in last_seen and pkt.ts - last_seen[cur_key] > self.flow_timeout:
                # Timeout: retire old flow, create a new one under a split key
                split_counts[base_key] += 1
                cur_key = base_key + (split_counts[base_key],)
                active_key[base_key] = cur_key

            if cur_key not in flows:
                # Determine canonical src/dst for the new flow record.
                # For a split key (len > 5), recover src/dst from base_key.
                if self.bidirectional:
                    src_ip, dst_ip, src_port, dst_port, proto = base_key
                else:
                    src_ip, dst_ip, src_port, dst_port, proto = (
                        pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto
                    )
                flows[cur_key] = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                )
                active_key[base_key] = cur_key

            flows[cur_key].add(pkt)
            last_seen[cur_key] = pkt.ts

        return flows
