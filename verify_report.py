#!/usr/bin/env python3
"""
verify_report.py
================
Standalone script: run full verification analysis on an existing pcap
and print detailed evidence to stdout.  Designed to be run after
each individual attack capture for a quick sanity check.

Usage:
    python3 verify_report.py --pcap ~/captures/PortScan_*.pcap \\
                             --label PortScan \\
                             --attacker-ip 10.0.0.10

Also provides:
    --wireshark-filters    Print the Wireshark display filters for manual
                            inspection (put these in your dissertation).
    --victim-log <path>    Path to /var/log/auth.log or access.log; counts
                            relevant lines to fill victim_log_hits.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ids_capture import Verifier


# ---------------------------------------------------------------------------
# Wireshark display filter library (dissertation Section 6.1)
# ---------------------------------------------------------------------------

WIRESHARK_FILTERS: dict[str, list[str]] = {
    "PortScan": [
        "tcp.flags.syn==1 && tcp.flags.ack==0",
        "ip.src=={attacker}",
    ],
    "SSHBruteForce": [
        "tcp.port==22",
        "ip.src=={attacker}",
    ],
    "WebBruteForce": [
        'http.request.method=="POST"',
        'http.request.uri contains "brute"',
        "ip.src=={attacker}",
    ],
    "SQLInjection": [
        'http.request.uri contains "UNION"',
        'http.request.uri contains "%27"',
        'http.request.uri contains "SELECT"',
        "ip.src=={attacker}",
    ],
    "DoSSYNFlood": [
        "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src=={attacker}",
    ],
    "BENIGN": [
        "ip.src=={attacker}",
    ],
}

TSHARK_COMMANDS: dict[str, list[str]] = {
    "PortScan": [
        'tshark -r {pcap} -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l',
        'tshark -r {pcap} -Y "ip.src=={attacker}" -T fields -e tcp.dstport | sort -un | wc -l',
    ],
    "SSHBruteForce": [
        'tshark -r {pcap} -Y "tcp.port==22 && ip.src=={attacker}" | wc -l',
    ],
    "WebBruteForce": [
        'tshark -r {pcap} -Y "http.request && ip.src=={attacker}" | wc -l',
    ],
    "SQLInjection": [
        'tshark -r {pcap} -Y "http.request && ip.src=={attacker}" -T fields -e http.request.uri | grep -iE "union|select|or%201"',
    ],
    "DoSSYNFlood": [
        'tshark -r {pcap} -q -z io,stat,1',
        'tshark -r {pcap} -q -z conv,ip',
    ],
}


def _count_victim_log_hits(log_path: Path, label: str) -> int:
    """Count log lines relevant to the given attack label."""
    if not log_path.exists():
        return 0
    text = log_path.read_text(encoding="utf-8", errors="replace")
    patterns = {
        "SSHBruteForce": r"Failed password",
        "WebBruteForce": r"POST.*brute|POST.*login",
        "SQLInjection": r"GET.*UNION|GET.*SELECT|GET.*%27|GET.*sqli",
        "DoSSYNFlood": r"SYN|flood",
        "PortScan": r"nmap|scan",
    }
    pat = patterns.get(label)
    if not pat:
        return 0
    return len(re.findall(pat, text, re.IGNORECASE))


def print_wireshark_hints(label: str, attacker_ip: str, pcap: str) -> None:
    """Print Wireshark display filters and tshark commands for the label."""
    print("\n\u2500\u2500 Wireshark Display Filters \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
    filters = WIRESHARK_FILTERS.get(label, WIRESHARK_FILTERS.get("BENIGN", []))
    for f in filters:
        # Both WIRESHARK_FILTERS and TSHARK_COMMANDS now use {attacker}
        # as the placeholder; substitute consistently here.
        f_rendered = f.format(attacker=attacker_ip, pcap=pcap)
        print(f"  {f_rendered}")

    print("\n\u2500\u2500 Equivalent tshark Commands \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
    cmds = TSHARK_COMMANDS.get(label, [])
    for cmd in cmds:
        cmd_rendered = cmd.format(pcap=pcap, attacker=attacker_ip)
        print(f"  {cmd_rendered}")
    print()


def main() -> None:
    p = argparse.ArgumentParser(
        description="Verify a capture and print dissertation evidence.",
    )
    p.add_argument("--pcap", required=True, help="Path to pcap file")
    p.add_argument("--label", required=True, help="Attack label, e.g. PortScan")
    p.add_argument("--attacker-ip", default="10.0.0.10", help="Attacker VM IP")
    p.add_argument("--time-window", default="unknown", help="Time window string for the report table")
    p.add_argument("--victim-log", help="Path to /var/log/auth.log or access.log")
    p.add_argument("--wireshark-filters", action="store_true",
                   help="Print Wireshark filters and tshark commands")
    args = p.parse_args()

    pcap_path = Path(args.pcap).expanduser().resolve()
    if not pcap_path.exists():
        print(f"ERROR: pcap file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  Verification Report: {args.label}")
    print(f"  Pcap : {pcap_path.name}")
    print(f"  Src  : {args.attacker_ip}")
    print(f"{'='*55}\n")

    verifier = Verifier(
        pcap_path=pcap_path,
        label=args.label,
        attacker_ip=args.attacker_ip,
        time_window=args.time_window,
    )

    print("Running checks … (this may take a moment for large pcaps)\n")
    result = verifier.run_all_checks()

    # Fill in victim log hits if provided
    if args.victim_log:
        result.victim_log_hits = _count_victim_log_hits(
            Path(args.victim_log), args.label
        )

    print(result.summary())

    if args.wireshark_filters:
        print_wireshark_hints(args.label, args.attacker_ip, str(pcap_path))

    # Output the single-row Markdown table for copy-pasting into the dissertation
    print("\n── Dissertation Table Row ─────────────────────────")
    print(Verifier.build_markdown_table([result]))

    verdict = "PASS ✓" if result.verified else "FAIL ✗"
    print(f"\nVerification verdict: {verdict}")
    sys.exit(0 if result.verified else 1)


if __name__ == "__main__":
    main()
