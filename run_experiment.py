#!/usr/bin/env python3
"""
run_experiment.py
=================
Orchestrates the full IDS dissertation data-collection pipeline.

  Phase 3  → Dataset A: benign traffic
  Phase 4  → Dataset B: one capture per attack
  Phase 5  → Verification (tshark evidence + Markdown table)
  Phase 7  → Flow extraction + labelling → master CSV

Run on the VICTIM VM (or any machine that can see the traffic and has
dumpcap / tshark installed).  You run attacks manually from the ATTACKER
VM (Kali) while this script manages captures, timestamps, and labels.

Usage:
    sudo python3 run_experiment.py --interface enp0s3 \\
                                   --attacker-ip 10.0.0.10 \\
                                   --outdir ~/captures

Interactive mode (default): the script prompts you at each step.
Automated mode (--auto):    the script controls the attack subprocess
                             timing itself (only useful if both VMs are
                             scripted together via SSH).
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path

import pandas as pd

from ids_capture import (
    CaptureSession,
    FlowExtractor,
    LabelsLog,
    Verifier,
    VerificationResult,
    list_interfaces,
)


# ---------------------------------------------------------------------------
# Attack definitions
# ---------------------------------------------------------------------------

# Each entry describes one attack phase.
# 'auto_cmd' is the command run on the ATTACKER (only used in --auto mode).
ATTACK_PHASES = [
    {
        "label": "PortScan",
        "description": "nmap SYN + TCP connect + version scans",
        "default_duration": 120,
        "auto_cmd": (
            "sudo nmap -sS -p 1-1024 {victim_ip} && "
            "nmap -sT -p 1-1000 {victim_ip} && "
            "sudo nmap -sV {victim_ip}"
        ),
    },
    {
        "label": "SSHBruteForce",
        "description": "hydra SSH brute force with small wordlist",
        "default_duration": 120,
        "auto_cmd": (
            "hydra -l labuser -P /tmp/pass.txt ssh://{victim_ip}"
        ),
    },
    {
        "label": "WebBruteForce",
        "description": "hydra HTTP brute force on DVWA login page",
        "default_duration": 90,
        "auto_cmd": (
            "hydra {victim_ip} http-get-form "
            "'/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login"
            ":Username and/or password incorrect"
            ":H=Cookie: PHPSESSID={phpsessid}; security=low' "
            "-l admin -P /tmp/pass.txt"
        ),
    },
    {
        "label": "SQLInjection",
        "description": "sqlmap DVWA sqli endpoint",
        "default_duration": 120,
        "auto_cmd": (
            "sqlmap -u 'http://{victim_ip}/vulnerabilities/sqli/?id=1&Submit=Submit' "
            "--cookie='PHPSESSID={phpsessid}; security=low' --batch --dbs"
        ),
    },
    {
        "label": "DoSSYNFlood",
        "description": "hping3 TCP SYN flood (capped at 500,000 packets)",
        "default_duration": 30,
        "auto_cmd": (
            "sudo hping3 -S -p 80 -c 500000 {victim_ip}"
        ),
    },
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _print_banner(text: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def _prompt_continue(prompt: str = "Press ENTER when ready, or 'skip' to skip: ") -> bool:
    """Return True to continue, False to skip."""
    try:
        reply = input(prompt).strip().lower()
        return reply != "skip"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _check_prerequisites() -> None:
    """Warn if required tools are missing."""
    needed = ["dumpcap", "tshark"]
    missing = [t for t in needed if not subprocess.which(t)]
    if missing:
        print(
            f"[WARNING] Missing tools: {missing}\n"
            "  Install with: sudo apt install tshark wireshark-common\n"
            "  (tcpdump will be used as fallback for capture if dumpcap is absent)"
        )


# ---------------------------------------------------------------------------
# Phase 3: Benign capture
# ---------------------------------------------------------------------------

def run_benign(interface: str, outdir: Path, duration: int) -> Path:
    _print_banner("PHASE 3 — Dataset A: BENIGN traffic")
    print(
        "Generate ordinary traffic to the victim now:\n"
        "  • curl / browse DVWA pages\n"
        "  • ping -c 20 <victim>\n"
        "  • One SSH login with correct credentials\n"
        "  • FTP/SCP file transfer (optional)\n"
    )
    with CaptureSession(
        interface=interface,
        label="BENIGN",
        outdir=outdir,
    ) as cap:
        if duration > 0:
            cap.wait(duration)
        else:
            _prompt_continue("Generate benign traffic now. Press ENTER to stop capture: ")

    return cap.pcap_path


# ---------------------------------------------------------------------------
# Phase 4: Attack captures
# ---------------------------------------------------------------------------

def run_attacks(
    interface: str,
    outdir: Path,
    attacker_ip: str,
    victim_ip: str,
    auto: bool,
    phpsessid: str,
) -> list[Path]:
    _print_banner("PHASE 4 — Dataset B: ATTACK traffic")
    pcap_paths = []

    for phase in ATTACK_PHASES:
        label = phase["label"]
        desc = phase["description"]
        duration = phase["default_duration"]

        print(f"\n{'─'*50}")
        print(f"Attack: {label}  ({desc})")

        if not auto:
            if not _prompt_continue(f"  Start '{label}' capture? [ENTER=yes / skip]: "):
                print(f"  Skipping {label}.")
                continue

        with CaptureSession(
            interface=interface,
            label=label,
            outdir=outdir,
            # For DoS: cap file size to avoid filling disk
            ring_buffer_mb=512 if "Flood" in label or "DoS" in label else None,
            # Hard packet cap for SYN flood
            max_packets=600_000 if "Flood" in label else None,
        ) as cap:
            if auto:
                cmd = phase["auto_cmd"].format(
                    victim_ip=victim_ip,
                    attacker_ip=attacker_ip,
                    phpsessid=phpsessid,
                )
                print(f"  Running: {cmd}", flush=True)
                # Use a new process group so os.killpg terminates the whole
                # attack tool tree, not just the shell wrapper.
                # preexec_fn=None raises ValueError on Windows, so omit it.
                attack_kwargs: dict = {"shell": True}
                if sys.platform != "win32":
                    attack_kwargs["preexec_fn"] = os.setsid
                proc = subprocess.Popen(cmd, **attack_kwargs)
                cap.wait(duration)
                try:
                    if sys.platform != "win32":
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
            else:
                print(f"  [Capture running]  Run '{desc}' from Kali now.")
                _prompt_continue("  Press ENTER when attack is complete: ")

        pcap_paths.append(cap.pcap_path)

    # Filter out any None entries (captures that failed to start)
    return [p for p in pcap_paths if p is not None]


# ---------------------------------------------------------------------------
# Phase 5: Verification
# ---------------------------------------------------------------------------

def run_verification(
    outdir: Path,
    attacker_ip: str,
) -> list[VerificationResult]:
    _print_banner("PHASE 5 — Verification")
    labels_log = outdir / "labels.log"
    if not labels_log.exists():
        print("[WARNING] labels.log not found — skipping verification.")
        return []

    log = LabelsLog(labels_log)
    print(log.summary())

    results = []
    for pcap_file in sorted(outdir.glob("*.pcap")):
        # Determine label from filename prefix
        label_guess = pcap_file.stem.split("_")[0]
        # Find time window from labels log
        matching = [w for w in log.windows if w.label == label_guess]
        time_window = (
            f"{matching[0].start.strftime('%H:%M')} – "
            f"{matching[0].stop.strftime('%H:%M') if matching[0].stop else '?'}"
            if matching else "unknown"
        )

        print(f"\n  Verifying: {pcap_file.name} …", flush=True)
        v = Verifier(
            pcap_path=pcap_file,
            label=label_guess,
            attacker_ip=attacker_ip,
            time_window=time_window,
        )
        result = v.run_all_checks()
        print(result.summary())
        results.append(result)

    if results:
        table = Verifier.build_markdown_table(results)
        table_path = outdir / "verification_table.md"
        table_path.write_text(f"# Verification Table\n\n{table}\n", encoding="utf-8")
        print(f"\n[✓] Verification table saved: {table_path}")

    return results


# ---------------------------------------------------------------------------
# Phase 7: Flow extraction + labelling
# ---------------------------------------------------------------------------

def run_flow_extraction(
    outdir: Path,
    attacker_ip: str,
) -> Path:
    _print_banner("PHASE 7 — Flow Extraction & Labelling")
    labels_log = outdir / "labels.log"
    log = LabelsLog(labels_log) if labels_log.exists() else None

    all_dfs = []
    for pcap_file in sorted(outdir.glob("*.pcap")):
        label_guess = pcap_file.stem.split("_")[0]
        csv_path = outdir / f"{pcap_file.stem}_flows.csv"
        print(f"  Extracting flows: {pcap_file.name} …")

        extractor = FlowExtractor(
            pcap_path=pcap_file,
            output_csv=csv_path,
        )
        df = extractor.extract()

        if log:
            df = log.label_flows(df, attacker_ip=attacker_ip)
        else:
            # No labels.log — use the filename label for everything
            df["label"] = label_guess

        all_dfs.append(df)

    if not all_dfs:
        print("[WARNING] No pcap files found in outdir — nothing to extract.")
        master_path = outdir / "ids_dataset.csv"
        return master_path  # return expected type even when empty

    master = pd.concat(all_dfs, ignore_index=True)
    master_path = outdir / "ids_dataset.csv"
    master.to_csv(master_path, index=False)

    print(f"\n[✓] Master dataset: {master_path}")
    print(f"    Rows: {len(master):,}   Columns: {len(master.columns)}")
    print(f"    Label distribution:\n{master['label'].value_counts().to_string()}")

    return master_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_experiment.py",
        description="IDS dissertation: capture, verify, and label network traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--interface", "-i",
        help="Network interface to capture on (e.g. enp0s3, eth0). "
             "Leave blank to list available interfaces and exit.",
    )
    p.add_argument(
        "--attacker-ip",
        default="10.0.0.10",
        help="Attacker VM IP address [default: 10.0.0.10]",
    )
    p.add_argument(
        "--victim-ip",
        default="10.0.0.20",
        help="Victim VM IP address [default: 10.0.0.20]",
    )
    p.add_argument(
        "--outdir",
        default="~/captures",
        help="Output directory for pcap, labels.log, CSVs [default: ~/captures]",
    )
    p.add_argument(
        "--benign-duration",
        type=int,
        default=0,
        help="Seconds to capture benign traffic (0 = wait for ENTER) [default: 0]",
    )
    p.add_argument(
        "--auto",
        action="store_true",
        help="Automated mode: run attacks as subprocesses (experimental; "
             "works only when attacker commands are available locally).",
    )
    p.add_argument(
        "--phpsessid",
        default="changeme",
        help="DVWA PHPSESSID cookie value for automated web attacks.",
    )
    p.add_argument(
        "--skip-benign", action="store_true", help="Skip Phase 3 (benign capture)."
    )
    p.add_argument(
        "--skip-attacks", action="store_true", help="Skip Phase 4 (attack captures)."
    )
    p.add_argument(
        "--skip-verify", action="store_true", help="Skip Phase 5 (verification)."
    )
    p.add_argument(
        "--skip-extract", action="store_true", help="Skip Phase 7 (flow extraction)."
    )
    p.add_argument(
        "--verify-only",
        action="store_true",
        help="Only run verification on existing pcaps in --outdir.",
    )
    p.add_argument(
        "--extract-only",
        action="store_true",
        help="Only run flow extraction on existing pcaps in --outdir.",
    )
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    # List interfaces and exit if no interface given
    if not args.interface:
        print("Available network interfaces:\n")
        for iface in list_interfaces():
            print(f"  [{iface['index']}] {iface['name']}  (via {iface['source']})")
        print("\nRe-run with --interface <name>")
        sys.exit(0)

    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    _check_prerequisites()

    print(f"\n{'='*60}")
    print("  IDS DISSERTATION — PACKET CAPTURE PIPELINE")
    print(f"{'='*60}")
    print(f"  Interface  : {args.interface}")
    print(f"  Attacker IP: {args.attacker_ip}")
    print(f"  Victim IP  : {args.victim_ip}")
    print(f"  Output dir : {outdir}")
    print(f"  Mode       : {'AUTO' if args.auto else 'INTERACTIVE'}")
    print(f"{'='*60}\n")

    # ------------------------------------------------------------------
    # verify-only / extract-only shortcuts
    # ------------------------------------------------------------------
    if args.verify_only:
        run_verification(outdir, args.attacker_ip)
        return

    if args.extract_only:
        run_flow_extraction(outdir, args.attacker_ip)
        return

    # ------------------------------------------------------------------
    # Normal pipeline
    # ------------------------------------------------------------------
    if not args.skip_benign:
        run_benign(args.interface, outdir, args.benign_duration)

    if not args.skip_attacks:
        run_attacks(
            interface=args.interface,
            outdir=outdir,
            attacker_ip=args.attacker_ip,
            victim_ip=args.victim_ip,
            auto=args.auto,
            phpsessid=args.phpsessid,
        )

    if not args.skip_verify:
        run_verification(outdir, args.attacker_ip)

    if not args.skip_extract:
        run_flow_extraction(outdir, args.attacker_ip)

    _print_banner("Pipeline complete!")
    print(f"  All outputs saved to: {outdir}")
    print("  Next steps:")
    print("    1. Review verification_table.md")
    print("    2. Load ids_dataset.csv into your ML notebook")
    print("    3. Run Suricata: suricata -r <pcap> -l ./suricata_logs/")


if __name__ == "__main__":
    main()
