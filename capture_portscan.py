#!/usr/bin/env python3
"""
capture_portscan.py
===================
Standalone script to capture ONLY port scanning traffic.
Uses the existing ids_capture engine without modifying any other files.

Usage:
    # Use --interface enp0s3 for VirtualBox, or --interface ens33 for VMware.
    sudo python3 capture_portscan.py --interface enp0s3
    
Or, to filter specifically for the attacker's IP:
    sudo python3 capture_portscan.py --interface enp0s3 --extra-filter "host 10.0.0.10"
"""

import argparse
import sys
from pathlib import Path

from ids_capture import CaptureSession, list_interfaces

def main():
    p = argparse.ArgumentParser(description="Capture Port Scan traffic.")
    p.add_argument("--interface", "-i", help="Network interface to capture on.")
    p.add_argument("--outdir", default="~/captures", help="Output directory [default: ~/captures]")
    p.add_argument("--duration", type=int, default=0, help="Seconds to capture (0 = interactive manual stop) [default: 0]")
    p.add_argument("--extra-filter", default="", help="BPF filter string (e.g., 'host 10.0.0.10')")
    
    args = p.parse_args()

    # List interfaces if none is provided
    available_ifaces = list_interfaces()
    if not args.interface:
        print("Available network interfaces:\n")
        for iface in available_ifaces:
            print(f"  [{iface['index']}] {iface['name']}  (via {iface['source']})")
        print("\nRe-run with --interface <name>")
        sys.exit(0)

    valid_names = [i["name"] for i in available_ifaces]
    if args.interface not in valid_names:
        print(f"\n[ERROR] Interface '{args.interface}' does not exist on this system.")
        sys.exit(1)

    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    print("\n============================================================")
    print("  PORT SCAN CAPTURE")
    print("============================================================")
    print(f"  Interface : {args.interface}")
    print(f"  Output dir: {outdir}")
    if args.extra_filter:
        print(f"  BPF Filter: {args.extra_filter}")
    print("============================================================\n")
    
    with CaptureSession(
        interface=args.interface,
        label="PortScan",
        outdir=outdir,
        extra_filter=args.extra_filter,
    ) as cap:
        if args.duration > 0:
            cap.wait(args.duration)
        else:
            try:
                input("  [Capture running] Run your nmap scan from the attacker VM now. Press ENTER to stop: ")
            except (EOFError, KeyboardInterrupt):
                print()

    print(f"\n[✓] Capture complete!")
    print(f"    PCAP file saved to: {cap.pcap_path}")

if __name__ == "__main__":
    main()
