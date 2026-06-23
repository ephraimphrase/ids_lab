"""
ids_capture/verify.py
=====================
Post-capture verification engine — Phase 5 of the dissertation guide.

Runs tshark queries against a pcap and cross-references them with the
 labels.log ground truth, producing:
   - A VerificationResult per attack (packet counts, IPs, times)
   - A formatted Markdown verification table (Section 6.4 of the guide)

Usage:
    from ids_capture.verify import Verifier
    v = Verifier(
        pcap_path="~/captures/PortScan_20260623_140200.pcap",
        label="PortScan",
        attacker_ip="10.0.0.10",
    )
    result = v.run_all_checks()
    print(Verifier.build_markdown_table([result]))
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    label: str
    pcap: str
    attacker_ip: str
    time_window: str                    # "HH:MM – HH:MM" string from labels.log
    total_packets: int = 0
    syn_only_count: int = 0             # TCP SYN without ACK
    unique_dst_ports: int = 0           # distinct destination ports hit
    http_request_count: int = 0         # total HTTP GET/POST
    sql_keyword_count: int = 0          # URIs with SQL syntax
    ssh_packet_count: int = 0           # packets on tcp/22
    peak_pps: float = 0.0               # packets/second peak (DoS metric)
    avg_pps: float = 0.0                # mean packets/second
    victim_log_hits: int = 0            # filled in externally if available
    errors: list[str] = field(default_factory=list)
    verified: bool = False              # set True when evidence is sufficient

    def summary(self) -> str:
        lines = [
            f"Label          : {self.label}",
            f"Pcap           : {self.pcap}",
            f"Time window    : {self.time_window}",
            f"Attacker IP    : {self.attacker_ip}",
            f"Total packets  : {self.total_packets:,}",
            f"SYN-only pkts  : {self.syn_only_count:,}",
            f"Unique dst ports: {self.unique_dst_ports:,}",
            f"HTTP requests  : {self.http_request_count:,}",
            f"SQLi keywords  : {self.sql_keyword_count:,}",
            f"SSH packets    : {self.ssh_packet_count:,}",
            f"Peak PPS       : {self.peak_pps:.1f}",
            f"Mean PPS       : {self.avg_pps:.1f}",
            f"Victim log hits: {self.victim_log_hits:,}",
            f"Verified       : {'✓ YES' if self.verified else '✗ NO'}",
        ]
        if self.errors:
            lines.append("Errors         : " + "; ".join(self.errors))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class Verifier:
    """
    Runs a set of tshark-based checks against a single pcap file and
    returns a VerificationResult.

    Requires tshark on PATH.  Install with:
        sudo apt install tshark    (Debian/Ubuntu)
        brew install wireshark     (macOS)
    """

    # SQL keywords to look for in HTTP URIs (case-insensitive, URL-encoded variants included)
    _SQL_PATTERNS = [
        "UNION", "SELECT", "INSERT", "DROP", "OR%201", "OR+1",
        "sleep(", "benchmark(", "WAITFOR", "%27", "' OR", "1=1",
    ]

    def __init__(
        self,
        pcap_path: str | Path,
        label: str,
        attacker_ip: str,
        time_window: str = "unknown",
    ):
        self.pcap = Path(pcap_path).expanduser().resolve()
        self.label = label
        self.attacker_ip = attacker_ip
        self.time_window = time_window
        self._tshark = shutil.which("tshark")
        if not self._tshark:
            raise RuntimeError(
                "tshark not found on PATH. Install with: sudo apt install tshark"
            )

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run_all_checks(self) -> VerificationResult:
        """Run every applicable check and return a populated result."""
        result = VerificationResult(
            label=self.label,
            pcap=str(self.pcap),
            attacker_ip=self.attacker_ip,
            time_window=self.time_window,
        )

        if not self.pcap.exists():
            result.errors.append(f"pcap file not found: {self.pcap}")
            return result

        result.total_packets = self._count_total_packets()
        result.syn_only_count = self._count_syn_only(self.attacker_ip)
        result.unique_dst_ports = self._count_unique_dst_ports(self.attacker_ip)
        result.http_request_count = self._count_http_requests(self.attacker_ip)
        result.sql_keyword_count = self._count_sql_keywords(self.attacker_ip)
        result.ssh_packet_count = self._count_ssh_packets(self.attacker_ip)
        result.peak_pps, result.avg_pps = self._compute_pps()

        # Auto-verify heuristics (you can tune these thresholds)
        result.verified = self._auto_verify(result)
        return result

    @staticmethod
    def build_markdown_table(results: list[VerificationResult]) -> str:
        """
        Build the dissertation verification table (Section 6.4) from a list
        of results, one per attack.  Returns a Markdown string.
        """
        header = (
            "| Attack | Time Window | Source IP | Total Pkts | "
            "SYN-only | Unique Ports | HTTP Reqs | SQLi Keywords | "
            "SSH Pkts | Peak PPS | Victim Log | Verified |\n"
            "|--------|-------------|-----------|------------|"
            "----------|--------------|-----------|---------------|"
            "----------|----------|------------|----------|\n"
        )
        rows = []
        for r in results:
            verified_str = "✓ Yes" if r.verified else "✗ No"
            victim_log = str(r.victim_log_hits) if r.victim_log_hits else "n/a"
            rows.append(
                f"| {r.label} | {r.time_window} | {r.attacker_ip} "
                f"| {r.total_packets:,} | {r.syn_only_count:,} "
                f"| {r.unique_dst_ports:,} | {r.http_request_count:,} "
                f"| {r.sql_keyword_count:,} | {r.ssh_packet_count:,} "
                f"| {r.peak_pps:.0f} | {victim_log} | {verified_str} |"
            )
        return header + "\n".join(rows)

    # ------------------------------------------------------------------
    # tshark wrappers
    # ------------------------------------------------------------------

    def _run_tshark(self, args: list[str]) -> str:
        """Run tshark with additional args and return stdout as a string."""
        cmd = [self._tshark, "-r", str(self.pcap), "-n"] + args
        try:
            return subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True, timeout=120
            )
        except subprocess.CalledProcessError as exc:
            # Non-zero exit: tshark found no matching packets (exit 2) or had
            # an error (exit 1).  Return empty string; caller handles zero count.
            # Print a debug hint so a developer can diagnose filter issues.
            if exc.returncode not in (1, 2):
                print(
                    f"[verify] tshark exited {exc.returncode} for: {' '.join(cmd)}",
                    flush=True,
                )
            return ""
        except subprocess.TimeoutExpired:
            print(f"[verify] tshark timed out for: {' '.join(cmd)}", flush=True)
            return ""

    def _count_total_packets(self) -> int:
        """Total packet count in the pcap."""
        out = self._run_tshark(["-T", "fields", "-e", "frame.number"])
        lines = [ln for ln in out.strip().splitlines() if ln.strip()]
        return len(lines)

    def _count_syn_only(self, src_ip: str) -> int:
        """Count TCP SYN packets without ACK — the port scan / SYN flood signature."""
        out = self._run_tshark([
            "-Y", f"tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src=={src_ip}",
            "-T", "fields", "-e", "frame.number",
        ])
        return len([ln for ln in out.strip().splitlines() if ln.strip()])

    def _count_unique_dst_ports(self, src_ip: str) -> int:
        """Count distinct destination TCP ports hit by attacker — port scan proof."""
        out = self._run_tshark([
            "-Y", f"ip.src=={src_ip} && tcp",
            "-T", "fields", "-e", "tcp.dstport",
        ])
        ports = set(ln.strip() for ln in out.strip().splitlines() if ln.strip())
        return len(ports)

    def _count_http_requests(self, src_ip: str) -> int:
        """Count HTTP GET/POST requests from the attacker (brute-force / SQLi)."""
        out = self._run_tshark([
            "-Y", f"http.request && ip.src=={src_ip}",
            "-T", "fields", "-e", "frame.number",
        ])
        return len([ln for ln in out.strip().splitlines() if ln.strip()])

    def _count_sql_keywords(self, src_ip: str) -> int:
        """Count HTTP requests whose URI contains SQL injection keywords."""
        out = self._run_tshark([
            "-Y", f"http.request && ip.src=={src_ip}",
            "-T", "fields", "-e", "http.request.uri",
        ])
        uris = out.strip().splitlines()
        count = 0
        for uri in uris:
            upper = uri.upper()
            if any(kw.upper() in upper for kw in self._SQL_PATTERNS):
                count += 1
        return count

    def _count_ssh_packets(self, src_ip: str) -> int:
        """Count packets on TCP/22 from the attacker — SSH brute-force proof."""
        out = self._run_tshark([
            "-Y", f"tcp.port==22 && ip.src=={src_ip}",
            "-T", "fields", "-e", "frame.number",
        ])
        return len([ln for ln in out.strip().splitlines() if ln.strip()])

    def _compute_pps(self) -> tuple[float, float]:
        """
        Compute peak and mean packets-per-second using tshark's io,stat.
        Uses 1-second intervals.  Returns (peak_pps, mean_pps).

        Handles both tshark 2.x format:
            |   1   | 0.000000 <-> 1.000000 |     142 |  23456 |
        and tshark 3.x / 4.x format:
            | 0 <> 1.000000 |      47 |    8596 |
        by extracting the first bare integer column that appears after a
        time-range column (identified by the '<>' separator).
        """
        out = self._run_tshark(["-q", "-z", "io,stat,1"])
        peak = 0.0
        counts = []
        for line in out.splitlines():
            # Skip header / separator lines
            if "<>" not in line and "<->" not in line:
                continue
            # Extract all pipe-delimited fields
            fields = [f.strip() for f in line.split("|") if f.strip()]
            # The packet count is the first purely numeric field after the
            # time-range field.  Find the time-range field index first.
            time_range_idx = next(
                (i for i, f in enumerate(fields) if "<>" in f or "<->" in f), None
            )
            if time_range_idx is None:
                continue
            # Walk fields after the time range and grab the first integer
            for f in fields[time_range_idx + 1:]:
                try:
                    pps = float(f)
                    counts.append(pps)
                    if pps > peak:
                        peak = pps
                    break
                except ValueError:
                    continue
        mean = sum(counts) / len(counts) if counts else 0.0
        return peak, mean

    # ------------------------------------------------------------------
    # Auto-verify heuristics
    # ------------------------------------------------------------------

    def _auto_verify(self, r: VerificationResult) -> bool:
        """
        Simple heuristic to mark a capture as 'verified' based on what
        traffic we'd expect for each label.  These thresholds are conservative
        starting points — tune them for your actual experiment.
        """
        label_up = self.label.upper()

        if "SCAN" in label_up:
            # A real scan should hit many ports with SYN-only packets.
            # Note: 'PORTSCAN' always contains 'SCAN', no separate check needed.
            return r.syn_only_count > 100 and r.unique_dst_ports > 100

        if "BRUTE" in label_up and "SSH" in label_up:
            return r.ssh_packet_count > 50

        if "BRUTE" in label_up or "WEBBRUTE" in label_up:
            return r.http_request_count > 20

        if "SQL" in label_up or "SQLI" in label_up:
            return r.sql_keyword_count > 0 and r.http_request_count > 5

        if "DOS" in label_up or "FLOOD" in label_up or "SYN" in label_up:
            return r.peak_pps > 1000 or r.syn_only_count > 10_000

        if "BENIGN" in label_up:
            # Benign is "verified" when it has packets but no attack signatures
            return (
                r.total_packets > 0
                and r.syn_only_count < 500
                and r.sql_keyword_count == 0
            )

        # Unknown label — require at least some traffic from the attacker IP
        return r.total_packets > 0
