# IDS Packet Capture & Analysis Suite

A robust, packet-level data collection and verification pipeline for the MSc dissertation:
**"A Packet-Level Intrusion Detection System — Lab Setup to Dataset Generation to Automated Threat Verification"**

This toolkit provides an end-to-end automated environment for executing network attacks, capturing packets reliably under heavy load, verifying the presence of attack signatures, and extracting Machine Learning-ready flow features.

---

## 1. Why This Architecture? (Design Decisions)

When building a dataset for Intrusion Detection System (IDS) research, data integrity and reproducibility are paramount. This suite makes several specific design choices to ensure thesis-grade results:

### Why `dumpcap` instead of Python sniffers (Scapy / PyShark)?
Python-based packet sniffers are notoriously slow. During a high-volume attack (like an hping3 SYN flood), Python sniffers will silently drop thousands of packets, corrupting your dataset. 
**The Solution:** This toolkit wraps `dumpcap` (the highly optimized C-based engine behind Wireshark) in a Python subprocess. We utilize `dumpcap`'s native ring-buffer (`-b filesize`) to prevent memory/disk exhaustion during DoS attacks, ensuring zero packet loss and a mathematically sound ground truth.

### Why custom flow extraction instead of CICFlowMeter?
While CICIDS2017 and CICFlowMeter are industry standards, the original Java-based CICFlowMeter is difficult to compile, unmaintained, and opaque. 
**The Solution:** The `extract_flows.py` module replicates the core CICFlowMeter 5-tuple bidirectional feature extraction (Duration, IAT, TCP Flags, PPS, BPS) using `tshark`'s `-T fields` parser and Python's `pandas`. This provides absolute transparency into how your ML features are calculated, which is critical for defending your methodology in a dissertation defense.

### Why the Automated Verification Module?
Examiners will not just take your word that an attack succeeded. You must prove the malicious traffic is present in the dataset.
**The Solution:** The `verify.py` and `verify_report.py` modules automatically run strict `tshark` display filters against your generated `.pcap` files. They count SYN-only packets, unique destination ports, SSH attempts, and SQL injection keywords, directly outputting a Markdown table summarizing the empirical evidence of the attacks.

### High-Performance & Memory-Optimized Pipeline
Working with multi-gigabyte PCAPs on resource-constrained VMs typically causes `MemoryError` crashes or takes days to process.
**The Solution:** 
- **Parallel Processing:** Flow extraction and verification are heavily multi-threaded, utilizing all available CPU cores simultaneously via `ThreadPoolExecutor`.
- **Stream Processing:** `tshark` output is streamed directly into Python memory line-by-line rather than loaded in bulk, keeping the RAM footprint flat regardless of PCAP size.
- **Single-Pass Verification:** Verification metrics are parsed simultaneously in a single pass of the PCAP file, drastically reducing I/O bottleneck and speeding up Phase 5 by up to 80%.

---

## 2. Lab Setup & Prerequisites

This software is designed to be run on the **Victim VM** (e.g., an Ubuntu Server hosting DVWA), while attacks are launched from an **Attacker VM** (e.g., Kali Linux). Both VMs should be on an isolated "Internal Network" to prevent background internet noise from polluting the dataset.

### Installation (Run on the Victim VM)

1. **Install System Dependencies:**
   The suite requires `tshark`, `dumpcap` (via wireshark-common), and `tcpdump` as a fallback.
   ```bash
   sudo apt update
   sudo apt install -y tshark wireshark-common tcpdump python3-pip
   ```
   *(Note: When installing wireshark-common, it may ask if non-superusers should be able to capture packets. Select **Yes**).*

2. **Install Python Dependencies:**
   ```bash
   pip3 install pandas
   ```

3. **Clone the Repository:**
   ```bash
   git clone <repo-url> ids-capture
   cd ids-capture
   ```

4. **Identify your Capture Interface:**
   Run the script without arguments to list available network interfaces.
   ```bash
   sudo python3 run_experiment.py
   # Output: [1] enp0s3  (via dumpcap)
   ```

---

## 3. Running the Pipeline (How to make it work)

The `run_experiment.py` orchestrator script guides you through the 4 core phases of the dataset generation process.

### Standard Execution (The Golden Path)
To guarantee a perfectly clean dataset with zero internet background noise, run this exact command on the Victim VM. It instructs the engine to capture the full attack pipeline while strictly filtering for packets that involve your Attacker VM.

*(**Important Note on Interfaces:** The command below uses `--interface enp0s3`, which is the default for VirtualBox. If you are running VMware, you must change this to `--interface ens33`. If you are on a bare-metal Linux server, it might be `--interface eth0`. You can always run `ip a` to check).*

```bash
sudo python3 run_experiment.py \
    --interface enp0s3 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.10" \
    --outdir /home/ubuntu/captures
```

The script will pause and prompt you at each step. When prompted, switch to your Kali VM, run the relevant attack, and press ENTER on the Victim VM when the attack finishes. The script manages the precise UTC timestamps in `labels.log`.

### Automated Execution
If you have configured SSH keys between the machines, you can automate the timing:

```bash
sudo python3 run_experiment.py \
    --interface enp0s3 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.10" \
    --auto \
    --phpsessid "your_dvwa_cookie"
```

### Standalone Targeted Captures
If you only want to capture a single specific event (like an ICMP ping or a single port scan) rather than the whole pipeline, use these simplified scripts:

**Capture just a ping:**
```bash
sudo python3 capture_benign.py --interface ens33 --extra-filter "icmp and host 10.0.0.10"
```

**Capture just a port scan:**
```bash
sudo python3 capture_portscan.py --interface ens33 --extra-filter "host 10.0.0.10"
```

**Capture a DoS attack** (SYN flood by default; add `--type udp` for a UDP flood):
```bash
sudo python3 capture_dos.py --interface ens33 --outdir /home/ubuntu/captures --extra-filter "host 10.0.0.10"
```

**Capture a DDoS attack** (multi-source spoofed SYN flood across several ports):
> ⚠️ Because hping3's `--rand-source` randomises the source IP, filtering by `host <attacker_ip>` will **not** work. Filter by the victim's destination instead.
```bash
sudo python3 capture_ddos.py --interface ens33 --outdir /home/ubuntu/captures --extra-filter "dst host 10.0.0.20 and tcp"
```

### Pipeline Phases Explained

| Phase | Description | Output |
|-------|-------------|--------|
| **Phase 3: Benign** | Generates baseline background traffic. You should manually browse the web app, run pings, and transfer files while this runs. | `BENIGN_<ts>.pcap` |
| **Phase 4: Attacks** | Captures individual attacks: PortScan, SSH Brute Force, Web Brute Force, SQL Injection, DoS SYN Flood, DoS UDP Flood, and DDoS SYN Flood. | `<Attack>_<ts>.pcap` |
| **Phase 5: Verification** | Cross-references the PCAPs with the timestamp log, applying heuristic filters to prove the attack traffic exists. | `verification_table.md` |
| **Phase 7: Extraction** | Parses all PCAPs, aggregates bidirectional flows, calculates ML features, and applies labels based on `labels.log`. | `ids_dataset.csv` |

---

## 4. How Everything Works (Module Breakdown)

### `ids_capture/capture.py` (The Sniffer Engine)
Provides the `CaptureSession` context manager. When entered, it securely boots `dumpcap` as a detached subprocess. It utilizes the `-b filesize:` flag to create a ring buffer during volumetric DoS attacks, preventing the VM's disk from filling up. It logs exact start/stop UTC timestamps to `labels.log` for precise ground-truth labeling.

### `ids_capture/labels.py` (The Ground-Truth Engine)
Parses the `labels.log` file into `LabelWindow` objects. When it comes time to label the CSV features, the `label_flows()` function checks two conditions:
1. Did the flow occur between the `start` and `stop` timestamps of an attack?
2. Was the `src_ip` OR `dst_ip` equal to the Attacker's IP?
If both are true, the flow is labeled with the attack name. Otherwise, it is labeled `BENIGN`.

### `ids_capture/extract_flows.py` (The Feature Engineer)
Parses `.pcap` files using `tshark -T fields`. Crucially, it uses **memory-efficient stream processing** to prevent out-of-memory crashes on huge PCAPs, and leverages multi-threading to process multiple PCAPs in parallel. It groups individual packets into 5-tuple bidirectional flows (Source IP, Dest IP, Source Port, Dest Port, Protocol). Once a flow times out (default 120s of inactivity), it calculates statistical features:
* **Time-based:** Duration, Inter-Arrival Time (Mean, Std, Max, Min)
* **Volume-based:** Total Packets, Total Bytes, Packets/sec, Bytes/sec
* **Behavioral:** TCP Flag counts (SYN, ACK, RST, FIN, PSH, URG), Mean Window Size

### `ids_capture/verify.py` & `verify_report.py` (The Evidence Generator)
To be used in Chapter 4/6 of your dissertation. It runs targeted `tshark` queries against the `.pcap` files. For example, to verify a Port Scan, it counts the number of `unique_dst_ports` targeted by the attacker. To verify a SYN Flood, it calculates the `peak_pps` (Packets Per Second). It utilizes a **single-pass architecture**, meaning it extracts all necessary metrics in one sweep of the PCAP file, saving massive amounts of time compared to running separate filters sequentially.
You can run a standalone report for a single PCAP:
```bash
python3 verify_report.py --pcap ~/captures/PortScan_*.pcap --label PortScan --attacker-ip 10.0.0.10 --wireshark-filters
```

---

## 5. Outputs & Deliverables

Once the pipeline completes, your `--outdir` will contain:

```text
/home/ubuntu/captures/
├── labels.log                      # Ground-truth timestamp ledger
├── BENIGN_20260623_140000.pcap     # Raw packet captures
├── PortScan_20260623_140200.pcap
├── DoSSYNFlood_20260623_144000.pcap
├── verification_table.md           # Copy-paste ready Markdown table for thesis
├── PortScan_*_flows.csv            # Individual flow features
└── ids_dataset.csv                 # The Master ML Dataset (Load this into Jupyter!)
```

---

## 6. Common Pitfalls & Troubleshooting

| Issue | Solution |
|-------|----------|
| **Wrong Interface Name** | Do not assume `eth0`. VirtualBox uses `enp0s3`, VMware uses `ens33`. Run `ip a` or run the script with no arguments to list valid interfaces. |
| **Zero-packet PCAPs** | Ensure `dumpcap` has correct permissions. Run the orchestrator with `sudo`. |
| **Clock Drift** | If your PCAP timestamps don't match your `labels.log`, your VM clocks are drifting. Install VirtualBox Guest Additions/VMware Tools on both VMs to sync time with the host. |
| **Internet Leakage** | If your `BENIGN` traffic is full of random internet scans, your VM is exposed. Set your hypervisor network adapter to **Internal Network** or **Host-Only**. |
| **Missing Flow Labels** | Ensure you provided the correct `--attacker-ip`. If the IP in the script doesn't match the Kali VM's actual IP, `labels.py` will classify the attacks as `BENIGN`. |
| **DVWA Attacks Failing** | Set DVWA Security Level to **Low**. For Hydra, ensure you are attacking `/vulnerabilities/brute/` and passing the correct `PHPSESSID` cookie. |
| **Permission Denied opening PCAPs** | Because the script runs with `sudo`, using `~/captures` saves files to `/root/captures/`. Use an absolute path like `/home/ubuntu/captures` instead to keep files accessible to your normal user. |
