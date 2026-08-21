#!/usr/bin/env python3
"""
compare_suricata.py
====================
Standalone script: cross-references this project's own attack verification
results (verification_table.md, produced by run_experiment.py's Phase 5)
against Suricata's independent alert output for the same pcaps, producing
a single comparison table for dissertation write-up.

Assumes you have already:
  1. Run the full pipeline (or at least Phase 5) so --outdir contains
     verification_table.md.
  2. Run Suricata against every pcap in --outdir in offline mode, with
     output written to <outdir>/suricata_logs/<pcap_stem>/fast.log, e.g.:

        for f in ~/captures/*.pcap; do
          name=$(basename "$f" .pcap)
          mkdir -p ~/captures/suricata_logs/"$name"
          sudo suricata -r "$f" -l ~/captures/suricata_logs/"$name" \\
              -c /etc/suricata/suricata.yaml
        done

Usage:
    python3 compare_suricata.py --outdir ~/captures

Writes compare_suricata.md and compare_suricata.csv into --outdir, and
prints the same table to stdout.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Noise patterns
# ---------------------------------------------------------------------------
# Exact substrings identified by manually inspecting this project's own
# fast.log output: all three are Suricata's low-severity protocol-decoder
# layer noting something technically malformed about a packet (commonly a
# side effect of NIC checksum offloading in a virtualized lab, or of a raw
# flood attack's TCP state churn), not a purpose-built attack signature.
# Hardcoded deliberately, not inferred from priority/classification, so
# exactly what counts as "noise" here is transparent and can be quoted
# directly in a dissertation methodology section.
NOISE_PATTERNS = ["invalid checksum", "invalid ack", "SHUTDOWN RST"]

# Matches the message text between the two "[**]" markers in a fast.log
# line, e.g. "ET DROP Spamhaus DROP Listed Traffic Inbound group 27".
_MSG_RE = re.compile(r"\[\*\*\]\s*\[[^\]]*\]\s*(.*?)\s*\[\*\*\]")

# Collapses trailing "group N"-style numeric suffixes so near-identical
# alerts (e.g. Spamhaus DROP groups 2, 26, 27, 28, ...) count as one
# signature family in the summary rather than many separate one-off lines.
_GROUP_NUM_RE = re.compile(r"\bgroup\s+\d+\b", re.IGNORECASE)


def _normalize_message(msg: str) -> str:
    return _GROUP_NUM_RE.sub("group N", msg)


def _is_noise(line: str) -> bool:
    return any(p in line for p in NOISE_PATTERNS)


# ---------------------------------------------------------------------------
# verification_table.md parsing
# ---------------------------------------------------------------------------

def parse_verification_table(path: Path) -> dict[str, str]:
    """Return {label: verified_str} e.g. {'PortScan': '✓ Yes'}."""
    results: dict[str, str] = {}
    if not path.exists():
        return results

    lines = path.read_text(encoding="utf-8").splitlines()
    seen_header = False
    for line in lines:
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not seen_header:
            if cells and cells[0] == "Attack":
                seen_header = True
            continue
        if cells and set(cells[0]) <= {"-"}:
            continue  # markdown separator row
        if len(cells) < 2:
            continue
        label = cells[0]
        verified = cells[-1]
        results[label] = verified

    return results


# ---------------------------------------------------------------------------
# fast.log analysis
# ---------------------------------------------------------------------------

def analyze_fast_log(path: Path) -> tuple[int, int, list[tuple[str, int]]]:
    """Return (total_alerts, non_noise_alerts, top_non_noise_signatures)."""
    if not path.exists():
        return 0, 0, []

    total = 0
    non_noise_messages: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        total += 1
        if _is_noise(line):
            continue
        m = _MSG_RE.search(line)
        msg = _normalize_message(m.group(1)) if m else "(unparsed alert text)"
        non_noise_messages.append(msg)

    counts: dict[str, int] = {}
    for msg in non_noise_messages:
        counts[msg] = counts.get(msg, 0) + 1
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:3]

    return total, len(non_noise_messages), top


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_rows(outdir: Path) -> list[dict[str, str]]:
    verified_by_label = parse_verification_table(outdir / "verification_table.md")

    rows: list[dict[str, str]] = []
    for label in verified_by_label:
        pcaps = sorted(outdir.glob(f"{label}_*.pcap"))
        if not pcaps:
            continue
        pcap = pcaps[-1]  # most recent, if there were multiple attempts
        fast_log = outdir / "suricata_logs" / pcap.stem / "fast.log"

        total, non_noise, top = analyze_fast_log(fast_log)
        top_str = "; ".join(f"{msg} (×{count})" for msg, count in top) or "—"

        rows.append({
            "Attack": label,
            "Your Method (verify.py)": verified_by_label[label],
            "Suricata Total Alerts": str(total),
            "Suricata Non-Noise Alerts": str(non_noise),
            "Top Non-Noise Signature(s) Fired": top_str,
        })

    return rows


def render_markdown(rows: list[dict[str, str]]) -> str:
    if not rows:
        return "(no rows — did you run verify.py and Suricata first?)\n"
    headers = list(rows[0].keys())
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row[h] for h in headers) + " |")
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Compare this project's verification results against Suricata's alerts.",
    )
    p.add_argument(
        "--outdir",
        default="/home/ubuntu/captures",
        help="Directory containing verification_table.md, the pcaps, and suricata_logs/ [default: /home/ubuntu/captures]",
    )
    args = p.parse_args()

    outdir = Path(args.outdir).expanduser().resolve()
    if not (outdir / "verification_table.md").exists():
        print(
            f"[ERROR] {outdir / 'verification_table.md'} not found.\n"
            "        Run the pipeline's verification phase first "
            "(--verify-only, or the full pipeline).",
            file=sys.stderr,
        )
        sys.exit(1)
    if not (outdir / "suricata_logs").exists():
        print(
            f"[WARNING] {outdir / 'suricata_logs'} not found — "
            "Suricata columns will show 0 for every attack.\n"
            "          Run Suricata against each pcap first (see this file's docstring).",
            file=sys.stderr,
        )

    rows = build_rows(outdir)

    md = render_markdown(rows)
    print(md)

    md_path = outdir / "compare_suricata.md"
    md_path.write_text(f"# Suricata Comparison\n\n{md}", encoding="utf-8")

    csv_path = outdir / "compare_suricata.csv"
    if rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    print(f"[✓] Written: {md_path}")
    print(f"[✓] Written: {csv_path}")


if __name__ == "__main__":
    main()
