"""
ids_capture/capture.py
======================
Core packet capture engine for the IDS dissertation lab.

Wraps dumpcap (preferred) or tcpdump as a subprocess — never uses a Python
sniffer loop, which drops packets under DoS load (Section 3.2 of the guide).

Usage:
    from ids_capture.capture import CaptureSession
    with CaptureSession(interface="enp0s3", label="PortScan",
                        outdir="~/captures") as cap:
        # run your attack here, or wait, or call cap.wait()
        pass
    print(cap.pcap_path)   # full path to the written pcap
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
                # Format: "1. eth0 (description)"
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
            for line in f.readlines()[2:]:  # skip header rows
                name = line.split(":")[0].strip()
                if name:
                    interfaces.append({"index": "-", "name": name, "source": "/proc/net/dev"})
    except Exception:
        pass

    return interfaces


# ---------------------------------------------------------------------------
# CaptureSession
# ---------------------------------------------------------------------------

class CaptureSession:
    """
    Context-manager wrapper around dumpcap (preferred) or tcpdump.

    Parameters
    ----------
    interface : str
        Network interface to capture on, e.g. "enp0s3" or "eth0".
    label : str
        Human-readable label for this capture (e.g. "BENIGN", "PortScan").
        Written into labels.log and used to name the output pcap.
    outdir : str | Path
        Directory where pcap and labels.log are written.
        Created automatically if it does not exist.
    extra_filter : str, optional
        BPF capture filter string, e.g. "host 10.0.0.10".
        Leave blank to capture all traffic on the interface.
    snaplen : int
        Snapshot length in bytes. 0 = full packet (default, required for
        full reconstruction; acceptable for a dissertation lab).
    ring_buffer_mb : int, optional
        If set, dumpcap uses a ring buffer of this many MB, which prevents
        disk exhaustion during DoS attacks (a cap is better than an OOM crash).
    max_packets : int, optional
        Hard cap on the total number of packets captured.  Useful for short
        flood runs so the pcap stays a sane size.
    use_tcpdump : bool
        Force use of tcpdump even if dumpcap is available.  Useful for VMs
        that have tcpdump but not Wireshark/dumpcap.
    """

    def __init__(
        self,
        interface: str,
        label: str,
        outdir: str | Path = "~/captures",
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

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def pcap_path(self) -> Optional[Path]:
        return self._pcap_path

    @property
    def labels_log(self) -> Optional[Path]:
        return self._labels_log

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> "CaptureSession":
        """Start the capture subprocess.  Called automatically by __enter__."""
        self.outdir.mkdir(parents=True, exist_ok=True)

        safe_label = (
            self.label
            .replace(" ", "_")
            .replace("/", "-")
            .replace("\\", "-")
            .replace(":", "-")
            .replace("*", "-")
            .replace("?", "-")
            .replace('"', "-")
            .replace("<", "-")
            .replace(">", "-")
            .replace("|", "-")
        )
        timestamp_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_label}_{timestamp_tag}.pcap"
        self._pcap_path = self.outdir / filename
        self._labels_log = self.outdir / "labels.log"

        self._start_time = _utc_now()
        self._write_label_event("start")

        cmd = self._build_command()
        print(f"[capture] Starting: {' '.join(str(c) for c in cmd)}", flush=True)

        # Redirect stderr so dumpcap's stats don't flood the console.
        # preexec_fn=None is not a no-op on Windows — it raises ValueError,
        # so we must omit the keyword argument entirely when running on Windows.
        popen_kwargs: dict = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
        }
        if sys.platform != "win32":
            popen_kwargs["preexec_fn"] = os.setsid

        self._proc = subprocess.Popen(cmd, **popen_kwargs)
        # Give the sniffer a moment to open the socket before the caller
        # starts generating traffic.
        time.sleep(0.5)
        return self

    def stop(self) -> "CaptureSession":
        """Stop the capture subprocess.  Called automatically by __exit__."""
        if self._proc and self.is_running:
            # dumpcap and tcpdump both honour SIGINT for clean shutdown.
            if sys.platform == "win32":
                # On Windows, terminate() sends WM_CLOSE / TerminateProcess.
                # CTRL_C_EVENT (==0) only works for processes in the same
                # console group and is unreliable here.
                self._proc.terminate()
            else:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGINT)
                except OSError:
                    # Process already exited between is_running check and here
                    # (TOCTOU race) — nothing to kill.
                    pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()

        self._stop_time = _utc_now()
        # Guard: if start() was never called (or raised before setting _pcap_path)
        # _write_label_event would crash on _pcap_path.name — skip it safely.
        if self._pcap_path is not None:
            self._write_label_event("stop")

        # Report any drop stats printed by dumpcap to stderr.
        if self._proc and self._proc.stderr:
            stderr_out = self._proc.stderr.read().decode(errors="replace")
            if stderr_out.strip():
                print(f"[capture] Capture stderr output:\n{stderr_out}", flush=True)

        return self

    def wait(self, seconds: float) -> "CaptureSession":
        """Sleep while the capture runs (for scripted attack windows)."""
        print(f"[capture] Capturing '{self.label}' for {seconds}s …", flush=True)
        time.sleep(seconds)
        return self

    def summary(self) -> dict:
        """Return a dict describing this capture session."""
        size_bytes = self._pcap_path.stat().st_size if self._pcap_path and self._pcap_path.exists() else 0
        return {
            "label": self.label,
            "pcap": str(self._pcap_path),
            "start": self._start_time,
            "stop": self._stop_time,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / 1_048_576, 2),
        }

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

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
        return False  # do not suppress exceptions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_command(self) -> list[str]:
        """Build the dumpcap or tcpdump command list."""
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
        cmd = [
            dumpcap,
            "-i", self.interface,
            "-w", str(self._pcap_path),
            "-s", str(self.snaplen),
            "-q",           # quiet — suppress per-packet output
        ]
        if self.ring_buffer_mb:
            # Rotate after N MB; keep 2 files so the ring has somewhere to wrap
            # into before the first file is overwritten.  files:1 is a no-op ring
            # (immediately overwrites itself), files:2 is the practical minimum.
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
        # Only prepend sudo when not already running as root (uid 0).
        # Double-sudo causes "sudo: sudo: command not found" on some systems.
        already_root = (os.getuid() == 0) if hasattr(os, "getuid") else False
        prefix = [] if already_root else ["sudo"]
        cmd = prefix + [
            tcpdump,
            "-i", self.interface,
            "-w", str(self._pcap_path),
            "-s", str(self.snaplen),
            "--immediate-mode",
        ]
        if self.max_packets:
            cmd += ["-c", str(self.max_packets)]
        if self.extra_filter:
            # BPF filter must be the last argument and is a single string token
            cmd += self.extra_filter.split()
        return cmd

    def _write_label_event(self, event: str) -> None:
        """Append a start or stop event line to labels.log."""
        # Use the already-recorded timestamps for consistency with
        # self._start_time / self._stop_time rather than calling _utc_now() again.
        if event == "start":
            timestamp = self._start_time
        else:
            # _stop_time is set by stop() before this is called.
            timestamp = self._stop_time if self._stop_time else _utc_now()
        line = (
            f"LABEL  label={self.label!r:<20}  event={event:<5}  "
            f"time={timestamp}  pcap={self._pcap_path.name}\n"
        )
        # Use UTF-8 explicitly: label names and timestamps may contain
        # non-ASCII characters (e.g. em-dashes) on some locales.
        with open(self._labels_log, "a", encoding="utf-8") as f:
            f.write(line)
        print(f"[labels] {line.strip()}", flush=True)
