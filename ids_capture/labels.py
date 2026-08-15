"""
ids_capture/labels.py
=====================
Labels.log reader and labeller for the ML-ready dataset step (Phase 7).

The labels.log written by CaptureSession looks like:
    LABEL  label='PortScan'           event=start  time=2026-06-23T14:02:00Z  pcap=PortScan_20260623_140200.pcap
    LABEL  label='PortScan'           event=stop   time=2026-06-23T14:09:00Z  pcap=PortScan_20260623_140200.pcap

This module:
  1. Parses labels.log into a list of LabelWindow objects.
  2. Provides label_flows(df) which applies those windows to a flow CSV
     (output from CICFlowMeter / Zeek / custom extractor).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd


# ---------------------------------------------------------------------------
# LabelWindow
# ---------------------------------------------------------------------------

@dataclass
class LabelWindow:
    label: str          # e.g. "PortScan", "BENIGN"
    start: datetime     # UTC
    stop: Optional[datetime]   # None if no matching stop line yet
    pcap: str           # pcap filename (not full path)

    def contains(self, ts: datetime) -> bool:
        """True if ts (UTC-aware) falls inside [start, stop]."""
        if ts < self.start:
            return False
        if self.stop and ts > self.stop:
            return False
        return True


# ---------------------------------------------------------------------------
# LabelsLog
# ---------------------------------------------------------------------------

class LabelsLog:
    """
    Parse and query a labels.log file.

    Parameters
    ----------
    path : str | Path
        Path to the labels.log file.
    """

    # Regex to parse one log line
    _RE = re.compile(
        r"LABEL\s+label='?(?P<label>[^'\s]+)'?\s+"
        r"event=(?P<event>\w+)\s+"
        r"time=(?P<time>\S+)\s+"
        r"pcap=(?P<pcap>\S+)"
    )

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.windows: list[LabelWindow] = []
        self._parse()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def label_for_timestamp(self, ts: datetime) -> str:
        """
        Return the attack label that covers the given UTC timestamp,
        or 'BENIGN' if no attack window covers it.
        """
        # Make ts timezone-aware if it isn't
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        for w in self.windows:
            if w.label.upper() != "BENIGN" and w.contains(ts):
                return w.label
        return "BENIGN"

    def label_flows(
        self,
        df: pd.DataFrame,
        timestamp_col: str = "timestamp",
        src_ip_col: Optional[str] = "src_ip",
        attacker_ip: Optional[str] = "10.0.0.10",
        victim_ip: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        Apply ground-truth labels to a flow DataFrame.

        Labelling rule (matches CICIDS2017 methodology):
            - If src_ip == attacker_ip (or victim_ip, see below) AND the
              timestamp is within a recorded attack window → label =
              <attack name>
            - Otherwise → label = BENIGN

        Parameters
        ----------
        df : pd.DataFrame
            Flow records.  Must have a timestamp column and optionally a
            source-IP column.
        timestamp_col : str
            Name of the timestamp column.  Values should be parseable by
            pd.to_datetime().
        src_ip_col : str | None
            Name of the source-IP column.  Set to None to skip IP filtering
            (labels purely by time window).
        attacker_ip : str | None
            The attacker's IP.  Used to restrict labelling to flows
            originating from the attacker.
        victim_ip : str | None
            The victim's IP. Attacks that spoof their source IP (e.g.
            DDoSSYNFlood's --rand-source) never match attacker_ip on either
            side of a flow, so without this fallback every such flow falls
            through to BENIGN despite being squarely inside the attack's
            time window. Matching on the victim instead is safe here since
            each labelled window is attack-only -- no concurrent benign
            traffic is generated during it.

        Returns
        -------
        pd.DataFrame with a new 'label' column.
        """
        df = df.copy()

        # Normalise timestamps to UTC-aware
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], utc=True, errors="coerce")

        df["label"] = "BENIGN"

        for w in self.windows:
            if w.label.upper() == "BENIGN":
                continue  # don't relabel benign-window rows
            if w.stop is None:
                continue  # incomplete window (no stop line) — skip

            # Convert Python datetime to pd.Timestamp to avoid FutureWarning
            # in pandas ≥2.0 when comparing DatetimeTZDtype with datetime objects.
            w_start = pd.Timestamp(w.start)
            w_stop = pd.Timestamp(w.stop)

            time_mask = (df[timestamp_col] >= w_start) & (df[timestamp_col] <= w_stop)

            if src_ip_col and (attacker_ip or victim_ip):
                # Match attacker on EITHER src or dst so bidirectional flows
                # (where the canonical key may store victim IP as src_ip) are
                # still correctly identified as attack traffic. Also match on
                # victim_ip as a fallback for spoofed-source attacks, where
                # neither side of the flow is ever the real attacker_ip.
                ip_col = df[src_ip_col].astype(str)
                dst_col = df["dst_ip"].astype(str) if "dst_ip" in df.columns else ip_col
                ip_mask = pd.Series(False, index=df.index)
                if attacker_ip:
                    ip_mask |= (ip_col == attacker_ip) | (dst_col == attacker_ip)
                if victim_ip:
                    ip_mask |= (ip_col == victim_ip) | (dst_col == victim_ip)
                mask = time_mask & ip_mask
            else:
                mask = time_mask

            df.loc[mask, "label"] = w.label

        return df

    def summary(self) -> str:
        """Print a human-readable summary of all parsed windows."""
        lines = [f"Labels.log: {self.path}", f"  {len(self.windows)} window(s) parsed:"]
        for w in self.windows:
            stop_str = w.stop.isoformat() if w.stop else "<no stop>"
            lines.append(f"  [{w.label}]  {w.start.isoformat()} → {stop_str}  ({w.pcap})")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _parse(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"labels.log not found: {self.path}")

        # Build a dict keyed by (label, pcap) → LabelWindow (mutated when stop found)
        pending: dict[tuple[str, str], LabelWindow] = {}

        with open(self.path, encoding="utf-8") as f:
            for line in f:
                m = self._RE.search(line)
                if not m:
                    continue
                label = m.group("label")
                event = m.group("event")
                raw_time = m.group("time")
                pcap = m.group("pcap")

                ts = self._parse_time(raw_time)
                key = (label, pcap)

                if event == "start":
                    pending[key] = LabelWindow(label=label, start=ts, stop=None, pcap=pcap)
                elif event == "stop":
                    if key in pending:
                        pending[key].stop = ts
                        self.windows.append(pending.pop(key))
                    else:
                        # Stop without matching start — create a closed window
                        # using start = stop (degenerate, for robustness)
                        self.windows.append(LabelWindow(label=label, start=ts, stop=ts, pcap=pcap))

        # Any unclosed windows (process killed before stop?) — add them open-ended
        for w in pending.values():
            self.windows.append(w)

    @staticmethod
    def _parse_time(raw: str) -> datetime:
        """Parse ISO-8601 or a few common variants, always return UTC-aware."""
        raw = raw.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # Last-resort: let dateutil handle it if installed
        try:
            from dateutil import parser as du_parser
            return du_parser.parse(raw).astimezone(timezone.utc)
        except ImportError:
            pass
        raise ValueError(f"Cannot parse timestamp: {raw!r}")
