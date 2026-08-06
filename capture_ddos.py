#!/usr/bin/env python3
"""
capture_ddos.py
===============
Standalone script to capture a simulated DDoS (Distributed Denial of Service) attack.

What makes DDoS different from DoS in this context:
  - DoS:  a single source IP floods the victim.
  - DDoS: many different source IPs flood the victim simultaneously (a botnet).

Since a real botnet is impractical in a lab, this is simulated using hping3's
'--rand-source' flag, which randomises the source IP per packet. The result is
traffic that closely mirrors the signature of a real DDoS: the victim receives
SYN packets from hundreds of different IP addresses at high volume.

On your Attacker VM (Kali), run the following commands in parallel before pressing
ENTER on this script:

    sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 80  <victim_ip> &
    sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 443 <victim_ip> &
    sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 22  <victim_ip> &
    wait

This hits three ports simultaneously from random sources, generating the
multi-source, multi-port signature characteristic of a DDoS attack.
Note: hping3's -c (packet count) option is ignored in --flood mode, so each
stream is bounded with 'timeout -s INT 2' instead -- adjust the '2' if you
want a longer/shorter burst.

Run this script on the VICTIM VM BEFORE starting the attack on the Attacker VM.

Usage:
    # Use --interface enp0s3 for VirtualBox, or --interface ens33 for VMware.
    sudo python3 capture_ddos.py --interface ens33 --extra-filter "dst host 10.0.0.20 and tcp"

    # Use an absolute outdir to avoid files being saved to /root/ when using sudo:
    sudo python3 capture_ddos.py --interface ens33 --outdir /home/ubuntu/captures

NOTE on --extra-filter for DDoS:
    Because hping3's '--rand-source' randomises the source IP, filtering by
    'host <attacker_ip>' will NOT capture any DDoS traffic. Use 'dst host <victim_ip>'
    to filter by destination (the victim) instead.
"""

# ---------------------------------------------------------------------------
# Self-contained engine (copied from ids_capture/capture.py)
# No external ids_capture dependency — this file runs standalone.
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _utc_now() -> str:
    """ISO-8601 timestamp in UTC, matching labels.log convention."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_binary(*names: str) -> Optional[str]:
    """Return the first name found on PATH, or None."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def list_interfaces() -> list[dict]:
    """
    Return a list of available network interfaces.
    Uses 'dumpcap -D' if available, else falls back to the 'ip' command,
    else reads /proc/net/dev.
    """
    interfaces = []

    # --- Try dumpcap -D ---
    dumpcap = _find_binary("dumpcap")
    if dumpcap:
        try:
            out = subprocess.check_output(
                [dumpcap, "-D"], stderr=subprocess.DEVNULL, text=True
            )
            for line in out.strip().splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) >= 2:
                    interfaces.append(
                        {"index": parts[0].rstrip("."), "name": parts[1], "source": "dumpcap"}
                    )
            return interfaces
        except Exception:
            pass

    # --- Try 'ip link' ---
    ip_bin = _find_binary("ip")
    if ip_bin:
        try:
            out = subprocess.check_output(
                [ip_bin, "-o", "link", "show"], stderr=subprocess.DEVNULL, text=True
            )
            for line in out.strip().splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    name = parts[1].strip().split("@")[0]
                    interfaces.append({"index": parts[0].strip(), "name": name, "source": "ip"})
            return interfaces
        except Exception:
            pass

    # --- Fallback: /proc/net/dev ---
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name = line.split(":")[0].strip()
                if name:
                    interfaces.append({"index": "-", "name": name, "source": "/proc/net/dev"})
    except Exception:
        pass

    return interfaces


class CaptureSession:
    """
    Context-manager wrapper around dumpcap (preferred) or tcpdump.
    Copied from ids_capture/capture.py to keep this script self-contained.
    """

    def __init__(
        self,
        interface: str,
        label: str,
        outdir: str | Path = "/home/ubuntu/captures",
        extra_filter: str = "",
        snaplen: int = 0,
        ring_buffer_mb: Optional[int] = None,
        max_packets: Optional[int] = None,
        use_tcpdump: bool = False,
    ):
        self.interface = interface
        self.label = label
        self.outdir = Path(outdir).expanduser().resolve()
        self.extra_filter = extra_filter
        self.snaplen = snaplen
        self.ring_buffer_mb = ring_buffer_mb
        self.max_packets = max_packets
        self.use_tcpdump = use_tcpdump

        self._proc: Optional[subprocess.Popen] = None
        self._start_time: Optional[str] = None
        self._stop_time: Optional[str] = None
        self._pcap_path: Optional[Path] = None
        self._labels_log: Optional[Path] = None

    @property
    def pcap_path(self) -> Optional[Path]:
        return self._pcap_path

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> "CaptureSession":
        self.outdir.mkdir(parents=True, exist_ok=True)
        safe_label = (
            self.label.replace(" ", "_").replace("/", "-").replace("\\", "-")
            .replace(":", "-").replace("*", "-").replace("?", "-")
            .replace('"', "-").replace("<", "-").replace(">", "-").replace("|", "-")
        )
        timestamp_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._pcap_path = self.outdir / f"{safe_label}_{timestamp_tag}.pcap"
        self._labels_log = self.outdir / "labels.log"
        self._start_time = _utc_now()
        self._write_label_event("start")
        cmd = self._build_command()
        print(f"[capture] Starting: {' '.join(str(c) for c in cmd)}", flush=True)
        popen_kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.PIPE}
        if sys.platform != "win32":
            popen_kwargs["preexec_fn"] = os.setsid
        self._proc = subprocess.Popen(cmd, **popen_kwargs)
        time.sleep(0.5)
        return self

    def stop(self) -> "CaptureSession":
        if self._proc and self.is_running:
            if sys.platform == "win32":
                self._proc.terminate()
            else:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGINT)
                except OSError:
                    pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._stop_time = _utc_now()
        if self._pcap_path is not None:
            self._write_label_event("stop")
        if self._proc and self._proc.stderr:
            stderr_out = self._proc.stderr.read().decode(errors="replace")
            if stderr_out.strip():
                print(f"[capture] Capture stderr output:\n{stderr_out}", flush=True)
        return self

    def wait(self, seconds: float) -> "CaptureSession":
        print(f"[capture] Capturing '{self.label}' for {seconds}s …", flush=True)
        time.sleep(seconds)
        return self

    def summary(self) -> dict:
        size_bytes = self._pcap_path.stat().st_size if self._pcap_path and self._pcap_path.exists() else 0
        return {
            "label": self.label,
            "pcap": str(self._pcap_path),
            "start": self._start_time,
            "stop": self._stop_time,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / 1_048_576, 2),
        }

    def __enter__(self) -> "CaptureSession":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.stop()
        s = self.summary()
        print(
            f"[capture] Session '{s['label']}' complete — "
            f"{s['size_mb']} MB written to {s['pcap']}",
            flush=True,
        )
        return False

    def _build_command(self) -> list[str]:
        if not self.use_tcpdump and _find_binary("dumpcap"):
            return self._build_dumpcap_cmd()
        elif _find_binary("tcpdump"):
            return self._build_tcpdump_cmd()
        else:
            raise RuntimeError(
                "Neither dumpcap nor tcpdump found on PATH. "
                "Install wireshark-common (dumpcap) or tcpdump."
            )

    def _build_dumpcap_cmd(self) -> list[str]:
        dumpcap = _find_binary("dumpcap")
        if dumpcap is None:
            raise RuntimeError("dumpcap disappeared from PATH between check and use.")
        cmd = [dumpcap, "-i", self.interface, "-w", str(self._pcap_path),
               "-s", str(self.snaplen), "-q"]
        if self.ring_buffer_mb:
            cmd += ["-b", f"filesize:{self.ring_buffer_mb * 1024}", "-b", "files:2"]
        if self.max_packets:
            cmd += ["-c", str(self.max_packets)]
        if self.extra_filter:
            cmd += ["-f", self.extra_filter]
        return cmd

    def _build_tcpdump_cmd(self) -> list[str]:
        tcpdump = _find_binary("tcpdump")
        if tcpdump is None:
            raise RuntimeError("tcpdump disappeared from PATH between check and use.")
        already_root = (os.getuid() == 0) if hasattr(os, "getuid") else False
        prefix = [] if already_root else ["sudo"]
        cmd = prefix + [tcpdump, "-i", self.interface, "-w", str(self._pcap_path),
                        "-s", str(self.snaplen), "--immediate-mode"]
        if self.max_packets:
            cmd += ["-c", str(self.max_packets)]
        if self.extra_filter:
            cmd += self.extra_filter.split()
        return cmd

    def _write_label_event(self, event: str) -> None:
        timestamp = self._start_time if event == "start" else (self._stop_time or _utc_now())
        line = (
            f"LABEL  label={self.label!r:<20}  event={event:<5}  "
            f"time={timestamp}  pcap={self._pcap_path.name}\n"
        )
        with open(self._labels_log, "a", encoding="utf-8") as f:
            f.write(line)
        print(f"[labels] {line.strip()}", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Capture a simulated multi-source DDoS SYN flood attack."
    )
    p.add_argument("--interface", "-i", help="Network interface to capture on.")
    p.add_argument(
        "--outdir",
        default="/home/ubuntu/captures",
        help="Output directory. Use an absolute path to avoid root ownership issues [default: /home/ubuntu/captures]",
    )
    p.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Seconds to capture (0 = interactive manual stop) [default: 0]",
    )
    p.add_argument(
        "--extra-filter",
        default="",
        help="BPF filter string to restrict capture. "
             "NOTE: because '--rand-source' spoofs source IPs, filtering by "
             "attacker IP will NOT work for DDoS. Filter by victim IP or port instead "
             "(e.g., 'dst host 10.0.0.20 and tcp').",
    )

    args = p.parse_args()

    # List interfaces and exit if none provided
    available_ifaces = list_interfaces()
    if not args.interface:
        print("Available network interfaces:\n")
        for iface in available_ifaces:
            print(f"  [{iface['index']}] {iface['name']}  (via {iface['source']})")
        print("\nRe-run with --interface <name>")
        sys.exit(0)

    # Validate the chosen interface actually exists
    valid_names = [i["name"] for i in available_ifaces]
    if args.interface not in valid_names:
        print(f"\n[ERROR] Interface '{args.interface}' does not exist on this system.")
        print(f"        Available interfaces: {', '.join(valid_names)}")
        print("        (If you are on VMware, you likely need 'ens33' or 'eth0')\n")
        sys.exit(1)

    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    print("\n============================================================")
    print("  DDOS CAPTURE  [DDoSSYNFlood]")
    print("============================================================")
    print(f"  Interface : {args.interface}")
    print(f"  Output dir: {outdir}")
    if args.extra_filter:
        print(f"  BPF Filter: {args.extra_filter}")
    print()
    print("  On your Attacker VM (Kali), run ALL of these at once:")
    print("      sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 80  <victim_ip> &")
    print("      sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 443 <victim_ip> &")
    print("      sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 22  <victim_ip> &")
    print("      wait")
    print()
    print("  NOTE: '--rand-source' spoofs the source IP, so filtering by")
    print("        attacker IP will NOT capture this traffic. If using")
    print("        --extra-filter, use 'dst host <victim_ip> and tcp' instead.")
    print("============================================================\n")

    with CaptureSession(
        interface=args.interface,
        label="DDoSSYNFlood",
        outdir=outdir,
        extra_filter=args.extra_filter,
        # Ring-buffer capped at 512 MB to prevent disk exhaustion during floods
        ring_buffer_mb=512,
        # Hard packet cap to prevent runaway captures
        max_packets=600_000,
    ) as cap:
        if args.duration > 0:
            cap.wait(args.duration)
        else:
            try:
                input(
                    "  [Capture running] Launch your DDoS attack on the attacker VM now. "
                    "Press ENTER to stop: "
                )
            except (EOFError, KeyboardInterrupt):
                print()

    print(f"\n[✓] Capture complete!")
    print(f"    PCAP file saved to: {cap.pcap_path}")


if __name__ == "__main__":
    main()
