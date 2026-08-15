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

### Manually Running the Attacks from Kali (Interactive Mode)

In the default (non-`--auto`) mode, `run_experiment.py` does **not** touch your Kali VM at all — it only manages the capture on the Victim side. At each attack phase it prints something like:

```
Attack: PortScan  (nmap SYN + TCP connect + version scans)
  Start 'PortScan' capture? [ENTER=yes / skip]:
  [Capture running]  Run 'nmap SYN + TCP connect + version scans' from Kali now.
  Press ENTER when attack is complete:
```

That's your cue to switch to the **Kali VM** and type the matching command yourself, then switch back to the Victim VM and press ENTER once it finishes. The exact commands the script expects for each phase (taken straight from its internal `ATTACK_PHASES` definitions) are, using this doc's example IPs (attacker `10.0.0.10`, victim `10.0.0.20`):

| Attack | Command to run on Kali |
|---|---|
| **PortScan** | `sudo nmap -sS -p 1-1024 10.0.0.20 && nmap -sT -p 1-1000 10.0.0.20 && sudo nmap -sV 10.0.0.20` |
| **SSHBruteForce** | `hydra -l labuser -P /tmp/pass.txt ssh://10.0.0.20` |
| **WebBruteForce** | `hydra 10.0.0.20 http-get-form '/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=PASTE_COOKIE_HERE; security=low:Username and/or password incorrect' -l admin -P /tmp/pass.txt` |
| **SQLInjection** | `sqlmap -u 'http://10.0.0.20/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='PHPSESSID=PASTE_COOKIE_HERE; security=low' --batch --dbs` |
| **DoSSYNFlood** | `sudo timeout -s INT 2 hping3 -S --flood -p 80 10.0.0.20` |
| **DoSUDPFlood** | `sudo timeout -s INT 2 hping3 --udp --flood -p 80 10.0.0.20` |
| **DDoSSYNFlood** | `sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 80 10.0.0.20 & sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 443 10.0.0.20 & sudo timeout -s INT 2 hping3 -S --flood --rand-source -p 22 10.0.0.20 & wait` |

**Before you start, set up on Kali:**
- `nmap`, `hydra`, `sqlmap`, and `hping3` ship with Kali by default — nothing to install there.
- Create `/tmp/pass.txt`, a small wordlist that **includes the real password** for `labuser` (SSH) and `admin` (DVWA). If the correct password isn't in the list, hydra never succeeds and Phase 5 verification will report the attack as unverified even though traffic was generated.
- `labuser` must exist as an actual SSH-enabled account on the Victim VM.
- Log into DVWA in a browser first (Security level set to **Low** — see the troubleshooting table below), then copy the `PHPSESSID` cookie value from your browser's dev tools and swap it in for `PASTE_COOKIE_HERE` in the WebBruteForce/SQLInjection commands — replace that whole word, don't leave any surrounding punctuation behind. Get a fresh cookie right before each run; repeated failed attempts can invalidate the session.

### Automated Execution
`--auto` mode skips the manual Kali step by running each phase's attack command as a **local subprocess on whichever machine is running `run_experiment.py`** — it does not SSH anywhere, despite the tool's docstring mentioning SSH. Concretely:

```bash
sudo python3 run_experiment.py \
    --interface enp0s3 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.10" \
    --auto \
    --phpsessid "your_dvwa_cookie"
```

For this to actually reproduce the two-VM attacker/victim design, `nmap`, `hydra`, `sqlmap`, and `hping3` would need to be installed **on the Victim VM itself**, and the traffic would effectively be self-targeted (loopback-style) rather than arriving from a separate Kali box over the wire — which changes what your capture actually proves. For a genuine dissertation-grade dataset with attacks visibly arriving from a distinct attacker IP, use **interactive mode** (above) with a real, separate Kali VM. Treat `--auto` as a convenience for smoke-testing the pipeline itself, not for generating your real dataset.

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

**Capture a DoS attack** (SYN flood by default, auto-stops after 2s; add `--type udp` for a UDP flood):
```bash
sudo python3 capture_dos.py --interface ens33 --outdir /home/ubuntu/captures --extra-filter "host 10.0.0.10"
```

**Capture a DDoS attack** (multi-source spoofed SYN flood across several ports, each auto-stops after 2s):
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

### Full CLI Reference (`run_experiment.py`)

| Flag | Default | Purpose |
|---|---|---|
| `--interface`, `-i` | *(none — lists interfaces and exits)* | Capture interface, e.g. `ens33` |
| `--attacker-ip` | `10.0.0.10` | Kali's IP — used for filtering and flow labelling |
| `--victim-ip` | `10.0.0.20` | This machine's IP — only used to build `--auto` attack commands |
| `--outdir` | `/home/ubuntu/captures` | Where pcaps, `labels.log`, and CSVs are written |
| `--benign-duration` | `0` (wait for ENTER) | Seconds to capture Phase 3 benign traffic; `0` prompts you to stop manually |
| `--extra-filter` | *(none)* | BPF capture filter applied to every capture, e.g. `"host 10.0.0.10"` |
| `--auto` | off | Run attack commands automatically instead of prompting — see caveats above |
| `--phpsessid` | `changeme` | DVWA session cookie substituted into the WebBruteForce/SQLInjection `--auto` commands |
| `--skip-benign` | off | Skip Phase 3 entirely |
| `--skip-attacks` | off | Skip Phase 4 entirely |
| `--skip-verify` | off | Skip Phase 5 entirely |
| `--skip-extract` | off | Skip Phase 7 entirely |
| `--verify-only` | off | Run **only** Phase 5 against pcaps already in `--outdir` — useful for re-verifying without recapturing |
| `--extract-only` | off | Run **only** Phase 7 against pcaps already in `--outdir` — useful for re-extracting after a bug fix without recapturing |

`--skip-*` and `--verify-only`/`--extract-only` are the fast path when you're iterating on a bug in the extraction or verification code (as opposed to the capture itself) — you don't need to re-run the whole attack sequence every time.

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
| **When to stop the capture** | In interactive mode there is no capture timer — it runs until you press ENTER, regardless of `default_duration` (that value is only used in `--auto` mode). Don't press ENTER until the attack command has fully returned to your Kali shell prompt. For **PortScan**, the three chained `nmap` invocations can keep running (especially `-sV`) well after the visible output looks finished — wait for the prompt, not the scrollback. For **DoS/DDoS**, the commands below are wrapped in `timeout -s INT 2`, so `hping3` stops itself after 2 seconds and prints its summary stats automatically — just wait for that to appear. |
| **hping3 with `--flood` keeps running forever / ignores `-c`** | This is a real `hping3` behavior, not a misconfiguration: **`-c` (packet count) is silently ignored whenever `--flood` is used** — flood mode strips out the counting/reply-tracking bookkeeping entirely for maximum raw speed, so it never self-terminates and requires a manual Ctrl+C. The fix is to bound it by *time* instead of count: wrap the command in `timeout -s INT <seconds> hping3 ...` (the `-s INT` makes `timeout` send the same signal as Ctrl+C, so `hping3` still prints its clean summary instead of being abruptly killed). All DoS/DDoS commands in this doc and in `run_experiment.py`/`capture_dos.py`/`capture_ddos.py` now use this pattern with a 2-second window, which is plenty to clear `verify.py`'s `peak_pps > 1000` threshold — adjust the `2` if you want a longer/shorter burst. |
| **Wrong Interface Name** | Do not assume `eth0`. VirtualBox uses `enp0s3`, VMware uses `ens33`. Run `ip a` or run the script with no arguments to list valid interfaces. |
| **Zero-packet PCAPs** | Ensure `dumpcap` has correct permissions. Run the orchestrator with `sudo`. |
| **Clock Drift** | If your PCAP timestamps don't match your `labels.log`, your VM clocks are drifting. Install VirtualBox Guest Additions/VMware Tools on both VMs to sync time with the host. |
| **Internet Leakage** | If your `BENIGN` traffic is full of random internet scans, your VM is exposed. Set your hypervisor network adapter to **Internal Network** or **Host-Only**. |
| **Missing Flow Labels** | Ensure you provided the correct `--attacker-ip`. If the IP in the script doesn't match the Kali VM's actual IP, `labels.py` will classify the attacks as `BENIGN`. |
| **Hydra: "optional parameters must have the format X=value" / "no valid optional parameter type given: F"** | The full `http-get-form`/`http-post-form` syntax (confirmed via `hydra -U http-get-form` on the actual install) is `<url>:<form parameters>[:<optional>[:<optional>]]:<condition string>` — **the condition string is the LAST field**, after every optional parameter, not the third field. `H=`/`C=`/etc. go between the form parameters and the condition. The condition string is a bare string by default (meaning "failure"); it can optionally be prefixed `F=` or `S=`, but only in that final position — putting `F=` earlier, in the optional-parameter slot, is rejected since valid optional codes there are only `1, M, c, C, g, G, h, H`. Any literal colon inside an optional value (e.g. the `Cookie: PHPSESSID=...` header) must be escaped as `\:`. Use the corrected command in the table above: `...Login:H=Cookie\: PHPSESSID=...; security=low:Username and/or password incorrect`. |
| **Hydra reports every password as "valid" (e.g. "5 of 5 passwords found")** | This is a false positive: the failure string `"Username and/or password incorrect"` never appeared in the response, so hydra treats *absence of failure* as success. Re-run with `-d` (debug) and look for `[DEBUG] attempt result: found 0, redirect 1, location: ../../login.php` — if present, DVWA is redirecting every request to the login page before ever reaching the brute-force form, meaning your `PHPSESSID` isn't being recognized as an authenticated session. Causes seen in practice: (1) a stray character stuck onto the cookie value from copy/paste (e.g. a leftover `>` from a placeholder token — check the `[DATA] attacking ...` line at the top of `-d` output for the *exact* cookie hydra actually sent), or (2) a stale session — repeated failed hydra runs can invalidate it, so grab a fresh `PHPSESSID` right before each attempt rather than reusing one from earlier testing. |
| **Hydra/sqlmap Attacks "Failing" (0 hits in verification)** | Verification only passes if the credential in `/tmp/pass.txt` is actually correct — hydra/sqlmap running without ever succeeding still generates plenty of *traffic*, but `verify.py`'s heuristics key off request/packet counts, not login success. Set DVWA Security Level to **Low**, attack `/vulnerabilities/brute/`, and double-check the `PHPSESSID` cookie is current (it rotates on new sessions). |
| **Permission Denied opening PCAPs** | Because the script runs with `sudo`, every file it writes is root-owned. `run_experiment.py` now automatically hands `--outdir` back to the user who invoked `sudo` (via `SUDO_UID`/`SUDO_GID`) once it exits — success, early exit, or crash. This only fires when the process actually runs under `sudo`; if you still hit this, check you didn't pass `--outdir ~/captures` (which resolves to `/root/captures`, undoable by `chmod` alone since `/root` itself blocks non-root traversal) and that the process didn't get killed with `SIGKILL` (which skips the `finally` cleanup) — in that case, manually run `sudo chown -R $(whoami):$(whoami) <outdir>`. |
| **tshark fails with a specific exit code during Phase 5/7** | `extract_flows.py` and `verify.py` now include tshark's own `stderr` message in the warning instead of just the bare exit code. Two codes worth knowing: **3** = "isn't a capture file in a format TShark understands" (the pcap's header itself is corrupt/garbled — not just cut short); **14** = "cut short in the middle of a packet" (a genuinely truncated file, e.g. from an unclean kill). Run `file <pcap>` and `capinfos <pcap>` on the VM to inspect a suspect file directly. |
| **`tshark: You don't have permission to read the file` — even running as root, even after `chown`/`chmod`** | This is AppArmor confining `dumpcap`, not a normal Unix permission problem (root bypassing DAC checks is exactly what AppArmor exists to prevent). The tell: tshark also prints `Running as user "root" and group "root". This could be dangerous.` right before the denial. **`sudo systemctl stop apparmor` is not a reliable test** — it stops the systemd unit, but profiles already loaded into the kernel stay enforced regardless, so this can give a false "AppArmor isn't it" reading. The actual fix: `sudo aa-complain /usr/bin/dumpcap` (add `/usr/bin/tshark` too if it's also confined — check with `sudo aa-status`; the profile is sometimes registered as `tshark//dumpcap`, a child of the `tshark` profile, not a standalone `/usr/bin/dumpcap` entry — target the profile *file* directly instead, e.g. `sudo aa-complain /etc/apparmor.d/usr.bin.tshark`, to sidestep the naming ambiguity). This puts the profile in complain mode (logs violations instead of blocking) rather than disabling AppArmor system-wide. |
| **VMware: "The virtual machine's operating system has attempted to enable promiscuous mode on Ethernet0. This is not allowed for security reasons"** | Host-level VMware restriction, unrelated to anything inside the guest — by default only root on the *host* can grant promiscuous mode, and `/dev/vmnet*` is created root-only (`crw-------`). Fix on the **host**: `sudo chmod a+rw /dev/vmnet0 /dev/vmnet1 /dev/vmnet8`, then fully power-cycle the VM (guest reboot alone won't re-request it). This resets on host reboot since `udev` recreates the nodes root-only again — make it permanent with `echo 'KERNEL=="vmnet[0-9]*", MODE="0666"' \| sudo tee /etc/udev/rules.d/99-vmware-vmnet.rules && sudo udevadm control --reload-rules && sudo udevadm trigger`. In practice this specific warning rarely explains 0-byte captures on its own — this project only ever captures unicast traffic already addressed to the Victim's own interface, which doesn't require promiscuous mode — but it's cheap to fix and removes the variable. |
| **`dumpcap: ... could not be opened: Permission denied` when *writing* a new pcap (as opposed to tshark failing to *read* an existing one)** | Different failure mode from the read-side entry above, worth diagnosing separately rather than assuming it's the same cause. Confirm it's not a code/pipeline bug first by reproducing with the bare command directly (matches what `run_experiment.py` prints as `[capture] Starting: ...`): `sudo dumpcap -i <iface> -w <outdir>/test.pcap -s 0 -q -f "host <attacker_ip>"`. If that fails identically outside of Python entirely, work through this checklist in order (cheapest/most-likely first) rather than jumping straight to AppArmor: (1) `ls -ld <outdir>` — needs to be at least `777` (`chmod 777`); `chown` alone doesn't touch mode bits and `dumpcap`'s own default is `600`. (2) **`ls -ld` on the outdir's *parent*, e.g. `/home/<user>`** — Ubuntu often defaults new home directories to `750` (no access for "other"), and if `dumpcap` doesn't match the directory's owner or group it can't even traverse into it to reach `<outdir>`, regardless of how open `<outdir>` itself is; fix with `sudo chmod o+x /home/<user>` (traverse only, doesn't expose directory listing). (3) Only then check AppArmor (previous row) — confirm with `sudo aa-status` that a relevant profile is actually in *enforce* mode, and cross-check with `sudo dmesg \| grep -i apparmor` for an actual `apparmor="DENIED" ... comm="dumpcap"` line; complain mode alone doesn't prove AppArmor was ever the cause, and in one debugging session here it turned out not to be — the home-directory traverse bit was the real fix despite AppArmor having been part of the investigation. Why this needs checking at all under `sudo`/root: `dumpcap` ships with Linux file capabilities (`getcap /usr/bin/dumpcap` → `cap_net_raw,cap_net_admin=eip`), and per POSIX capability-exec rules, running a binary with explicit file capabilities computes its capability set from those rather than granting full root — so it ends up as EUID 0 *without* `CAP_DAC_OVERRIDE`, and is subject to normal permission bits just like any non-owning user. |
