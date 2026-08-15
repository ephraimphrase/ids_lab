# IDS Packet Capture & Analysis Suite

A robust, packet-level data collection and verification pipeline for the MSc dissertation:
**"A Packet-Level Intrusion Detection System — Lab Setup to Dataset Generation to Automated Threat Verification"**

This toolkit provides an end-to-end environment for executing network attacks, capturing packets reliably under heavy load, verifying the presence of attack signatures, and extracting Machine Learning-ready flow features — from a blank pair of VMs all the way to a labelled dataset and a Suricata comparison.

---

## 1. Why This Architecture? (Design Decisions)

When building a dataset for Intrusion Detection System (IDS) research, data integrity and reproducibility are paramount. This suite makes several specific design choices to ensure thesis-grade results:

### Why `dumpcap` instead of Python sniffers (Scapy / PyShark)?
Python-based packet sniffers are notoriously slow. During a high-volume attack (like an hping3 SYN flood), Python sniffers will silently drop thousands of packets, corrupting your dataset.
**The Solution:** This toolkit wraps `dumpcap` (the highly optimized C-based engine behind Wireshark) in a Python subprocess, logging exact start/stop UTC timestamps to `labels.log` for precise ground-truth labelling.

### Why custom flow extraction instead of CICFlowMeter?
While CICIDS2017 and CICFlowMeter are industry standards, the original Java-based CICFlowMeter is difficult to compile, unmaintained, and opaque.
**The Solution:** The `extract_flows.py` module replicates the core CICFlowMeter 5-tuple bidirectional feature extraction (Duration, IAT, TCP Flags, PPS, BPS) using `tshark`'s `-T fields` parser and Python's `pandas`. This provides absolute transparency into how your ML features are calculated, which is critical for defending your methodology in a dissertation defense.

### Why the Automated Verification Module?
Examiners will not just take your word that an attack succeeded. You must prove the malicious traffic is present in the dataset.
**The Solution:** The `verify.py` and `verify_report.py` modules automatically run targeted `tshark` queries against your generated `.pcap` files, counting SYN-only packets, unique destination ports, SSH attempts, HTTP requests, and SQL injection keywords, and output a Markdown table summarizing the empirical evidence of each attack.

### High-Performance & Memory-Optimized Pipeline
Working with multi-gigabyte PCAPs on resource-constrained VMs typically causes `MemoryError` crashes or takes days to process.
**The Solution:**
- **Parallel Processing:** Flow extraction and verification are multi-threaded, utilizing all available CPU cores via `ThreadPoolExecutor`.
- **Stream Processing:** `tshark` output is streamed directly into Python memory line-by-line rather than loaded in bulk, keeping the RAM footprint flat regardless of PCAP size.
- **Single-Pass Verification:** Verification metrics are parsed in a single sweep of the PCAP file, rather than running separate filters sequentially.

---

## 2. Full Environment Setup (From Blank VMs)

This software runs on a **Victim VM** (Ubuntu, hosting DVWA) while attacks are launched from an **Attacker VM** (Kali). This section assumes both are freshly installed on VMware and walks through everything needed to reach a working pipeline — this is hard-won, empirically verified setup knowledge, not a generic guide.

### 2.1 Network the two VMs together

Both VMs need to see each other's traffic directly, with zero internet noise polluting your BENIGN capture.

In VMware: **Edit → Virtual Network Editor** (or per-VM: right-click VM → Settings → Network Adapter), and set **both** VMs' adapters to the same **Host-only** network (or a custom VMnet/LAN Segment shared only between the two). Avoid NAT or Bridged for the actual lab network — those put you on a network with other traffic and possibly real internet access. (You will need to *temporarily* switch to NAT for installation steps that need internet — see 2.7.)

Give each VM a **static IP** so it never changes mid-project (DHCP renewal breaking `--attacker-ip`/`--victim-ip` is a common self-inflicted bug).

**Ubuntu (Victim)** — edit netplan (find your file with `ls /etc/netplan/`, typically `00-installer-config.yaml` from the subiquity installer):
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
# This is the network config written by 'subiquity'
network:
  ethernets:
    ens33:
      addresses: [10.0.0.20/24]
      dhcp4: false
      dhcp6: false
      match:
        macaddress: 00:0c:29:xx:xx:xx   # keep your actual MAC here
      set-name: ens33
  version: 2
```
```bash
sudo netplan apply
ip a show ens33   # confirm it shows 10.0.0.20/24
```
No `gateway4`/`nameservers` on purpose — this VM only needs to talk to Kali on the isolated segment; adding a gateway risks routing traffic out to the internet, which is exactly what you don't want polluting BENIGN captures. If `netplan apply` warns about file permissions, `sudo chmod 600 <file>` and retry. If it fails with `systemd-networkd is not running` / `dbus-org.freedesktop.network1.service not found`, first just check `ip a` — the fallback restart often still worked despite the noisy warning; if not, `sudo apt install -y apparmor-utils` isn't relevant here, instead try `sudo systemctl unmask systemd-networkd && sudo systemctl enable --now systemd-networkd && sudo netplan apply` , or if this VM actually uses NetworkManager instead, add `renderer: NetworkManager` to the YAML.

**Kali (Attacker)** — Kali doesn't use netplan, it uses NetworkManager directly:
```bash
ip a                      # confirm interface name, e.g. eth0
nmcli connection show     # find the connection name, usually "Wired connection 1"
sudo nmcli connection modify "Wired connection 1" ipv4.addresses 10.0.0.10/24
sudo nmcli connection modify "Wired connection 1" ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```

Verify: `ping 10.0.0.20` from Kali and `ping 10.0.0.10` from Ubuntu should both succeed.

### 2.2 Victim VM — base system setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tshark wireshark-common tcpdump python3-pip python3-venv git openssh-server apache2 mysql-server php php-mysqli php-gd libapache2-mod-php
```
The `wireshark-common` non-superuser prompt doesn't matter much here since the pipeline always runs under `sudo` anyway — either answer is fine.

**SSH brute-force target account** (username is hardcoded as `labuser` in `ATTACK_PHASES`, must match exactly):
```bash
sudo useradd -m -s /bin/bash labuser
sudo passwd labuser              # type a password interactively -- remember it, it goes in Kali's wordlist later
sudo grep -i passwordauthentication /etc/ssh/sshd_config   # must read 'yes'; edit + restart ssh if not
sudo systemctl restart ssh
```

**Disable fail2ban/ufw for the lab** — fail2ban will ban Kali's IP mid-brute-force and make every SSH attack look like it failed regardless of password correctness:
```bash
sudo systemctl stop fail2ban 2>/dev/null; sudo systemctl disable fail2ban 2>/dev/null
sudo ufw disable
```

### 2.3 Victim VM — DVWA via Docker

Manually installing DVWA (git clone + Apache + MySQL config) works too, but Docker is far less fiddly and is what this project actually uses:
```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo systemctl stop apache2 2>/dev/null; sudo systemctl disable apache2 2>/dev/null   # free up port 80 if it's running
sudo docker run -d --name dvwa -p 80:80 --restart unless-stopped vulnerables/web-dvwa
```
This image bundles Apache + PHP + MySQL internally — no separate database config needed — and serves DVWA at web root (`/`), matching every attack command in this doc (`/vulnerabilities/brute/`, `/vulnerabilities/sqli/`).

Then in a browser:
1. Visit `http://10.0.0.20/setup.php` → **Create / Reset Database**.
2. Log in with `admin` / `password`.
3. Set **DVWA Security** to **Low**.
4. This is also where you grab the current `PHPSESSID` cookie (browser dev tools → Application/Storage → Cookies) whenever you get to WebBruteForce/SQLInjection — it rotates on every new login, so grab it fresh each time, right before you need it.

To reset a broken container: `sudo docker rm -f dvwa`, then re-run the `docker run` command above.

### 2.4 Victim VM — get the pipeline code and Python deps

```bash
git clone https://github.com/ephraimphrase/ids_lab.git ~/ids_lab
cd ~/ids_lab
python3 -m venv venv
source venv/bin/activate
pip install pandas
```

**Important — `sudo` and venvs don't mix automatically.** `sudo python3 ...` starts a fresh process with a reset `PATH`, so it silently uses the *system* Python (no `pandas`), not your activated venv, even though your prompt still shows `(venv)`. Always invoke the venv's interpreter by path when using `sudo`:
```bash
sudo venv/bin/python3 run_experiment.py ...
```
not `sudo python3 run_experiment.py ...`.

If GitHub is blocked on your network (see §2.7 below for how to diagnose that), transfer the code some other way (a mirror, a direct file transfer, a temporary hotspot) — the rest of this doc doesn't depend on how the files got there.

### 2.5 Kali VM — wordlist

Build `/tmp/pass.txt`, containing the **real** passwords for both `labuser` (SSH) and DVWA's `admin` account (default `password` unless you changed it):
```bash
cat > /tmp/pass.txt << 'EOF'
123456
password
admin
YOUR_ACTUAL_LABUSER_SSH_PASSWORD
EOF
```
Put the real password near the top — both `SSHBruteForce` (120s) and `WebBruteForce` (90s default) windows are short, and a long wordlist may never reach the correct password in time. `nmap`, `hydra`, `sqlmap`, `hping3` all ship with Kali by default.

### 2.6 Victim VM — Suricata (for the comparison step at the end)

```bash
sudo apt install -y suricata
sudo suricata-update
```
Both steps need internet — see §2.7. Check `HOME_NET` in `/etc/suricata/suricata.yaml` covers your lab subnet (the default `10.0.0.0/8` already includes `10.0.0.0/24`, so usually no change needed).

### 2.7 Getting internet access for the install steps above

The isolated Host-only network from §2.1 has no route to the internet, which several install steps above need. Handle it with a temporary toggle:

1. VM → Settings → Network Adapter → switch to **NAT** → OK.
2. `sudo netplan apply` won't get you a NAT address if your netplan file is still pinned static — temporarily edit it back to `dhcp4: true` (remove the `addresses:` line), `sudo netplan apply`, confirm `ip a` shows a real NAT-range address (not `169.254.x.x`, which means no lease was obtained at all — modern Ubuntu doesn't ship `dhclient` anymore, netplan/`systemd-networkd` have DHCP built in).
3. Run your `apt`/`git`/`docker pull`/`suricata-update` steps.
4. Switch the adapter back to Host-only, restore the static netplan config from §2.1, `sudo netplan apply`, re-confirm `ping 10.0.0.10` still works.

**If a specific site (commonly GitHub) times out on port 443/80 while other sites work fine** (test with `curl -v https://<site> --max-time 10` — a `Connection timed out` on the specific IP, not a DNS failure, is the tell), that's not a VM problem — it's the *host network* (router/ISP-level filtering, or a security suite) blocking that one destination. Confirm by testing the same URL from the **host machine's own browser**; if it's blocked there too, it's not fixable from inside the VM. Router "Advanced Security"/parental-control features sometimes flag GitHub specifically since it hosts security tooling. A mobile hotspot or VPN sidesteps it.

### 2.8 Known first-boot environment issues to fix proactively

These three showed up, in this order, on a freshly rebuilt VM — fixing them now saves the exact same debugging loop later. All three manifest as some form of "0 bytes captured" or "permission denied," which is why it's worth doing this checklist *before* your first real run rather than chasing it attack-by-attack.

**A. VMware promiscuous-mode block** (host-side, not the guest) — shows as a VMware popup: *"The virtual machine's operating system has attempted to enable promiscuous mode on Ethernet0. This is not allowed for security reasons."* On the **host**:
```bash
ls -la /dev/vmnet*   # confirm they're crw------- (root-only) -- that's the cause
sudo chmod a+rw /dev/vmnet0 /dev/vmnet1 /dev/vmnet8
```
Then **fully power off** the Victim VM (guest reboot alone won't re-request it) and power it back on. Make it permanent so a host reboot doesn't undo it:
```bash
echo 'KERNEL=="vmnet[0-9]*", MODE="0666"' | sudo tee /etc/udev/rules.d/99-vmware-vmnet.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```
In practice this rarely explains 0-byte captures on its own — this project only captures unicast traffic already addressed to the Victim's own interface, which doesn't strictly need promiscuous mode — but it's cheap to fix and removes the variable.

**B. `dumpcap` write-permission chain** (Victim VM) — shows as `dumpcap: The file to which the capture would be saved ("...") could not be opened: Permission denied` when *writing* a new pcap. Root cause: `dumpcap` has Linux file capabilities set (`getcap /usr/bin/dumpcap` → `cap_net_raw,cap_net_admin=eip`), and per POSIX capability-exec rules that means it runs as EUID 0 **without** `CAP_DAC_OVERRIDE` even under `sudo` — so it's subject to normal permission bits just like any non-owning user. Two things need fixing, both one-time:
```bash
sudo chmod 777 ~/captures                 # dumpcap's own default file mode is 600; chown alone never touches mode bits
sudo chmod o+x /home/$(whoami)            # Ubuntu often defaults new home dirs to 750 -- "other" can't even traverse in to reach ~/captures otherwise
```
`run_experiment.py` now `chmod`s `--outdir` back to `777` automatically at the end of every run (alongside handing ownership back to you), so once this is done once, it should not recur for that directory — but a fresh `~/captures` on a rebuilt VM, or a different `--outdir`, needs it again.

**C. AppArmor confining `dumpcap`/`tshark`** — shows as `tshark: You don't have permission to read the file`, alongside the tell-tale `Running as user "root" and group "root". This could be dangerous.` line, when *reading* an existing pcap (as opposed to B's write-side failure). **Don't test this with `sudo systemctl stop apparmor`** — that stops the systemd unit but not profiles already loaded into the kernel, giving a false "it's not AppArmor" reading. Confirm properly first:
```bash
sudo apt install -y apparmor-utils
sudo aa-status   # look for tshark / tshark//dumpcap specifically under "enforce mode" vs "complain mode"
```
If it's enforcing, target the profile *file* directly (the profile is often registered as a `tshark//dumpcap` child hat, not a standalone `/usr/bin/dumpcap` entry, which trips up naming-by-path):
```bash
sudo aa-complain /etc/apparmor.d/usr.bin.tshark
```
Worth knowing: in one full debugging session on this project, AppArmor was suspected but ultimately *not* the actual cause — `dmesg | grep -i apparmor` showed zero `DENIED` entries for `tshark`/`dumpcap` the whole time, and the real fix was B above. Check `dmesg` for an actual `apparmor="DENIED" ... comm="dumpcap"` line before spending time here; don't assume AppArmor just because the error message pattern looks similar to a known AppArmor case.

### 2.9 Final pre-flight checklist

- [ ] `ping` works both directions, no internet leakage on this network segment
- [ ] `http://10.0.0.20/` loads DVWA's login page from a browser; DVWA Security = **Low**
- [ ] `ssh labuser@10.0.0.20` succeeds manually with the password that's in Kali's `/tmp/pass.txt`
- [ ] `fail2ban` stopped, `ufw` disabled on the Victim
- [ ] §2.8's three environment fixes applied
- [ ] `sudo venv/bin/python3 run_experiment.py` (no `--interface`) lists your real interface name

---

## 3. Running the Pipeline (How to make it work)

The `run_experiment.py` orchestrator script guides you through the 4 core phases of the dataset generation process.

### Standard Execution (The Golden Path)

*(**Interface name**: `enp0s3` for VirtualBox, `ens33` for VMware, `eth0` on bare metal — `ip a` to check.)*

*(**Filter**: use the **Victim's** IP, not the Attacker's. `DDoSSYNFlood`'s `--rand-source` spoofs the source IP on every packet, so `"host <attacker_ip>"` matches nothing during that phase and silently produces a 0-byte capture — `"host <victim_ip>"` matches every phase correctly since all attack traffic is destined to the Victim regardless of what source IP it claims. This doesn't affect labelling, which has its own independent victim-IP fallback — see §4.)*

```bash
sudo venv/bin/python3 run_experiment.py \
    --interface ens33 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.20" \
    --outdir /home/ubuntu/captures
```

The script pauses and prompts you at each step. When prompted, switch to Kali, run the relevant attack, and press ENTER on the Victim once it finishes. Precise UTC timestamps go to `labels.log` for ground-truth labelling.

### Manually Running the Attacks from Kali

In the default (non-`--auto`) mode, `run_experiment.py` never touches Kali at all — it only manages the capture on the Victim side. At each attack phase it prints:
```
Attack: PortScan  (nmap SYN + TCP connect + version scans)
  Start 'PortScan' capture? [ENTER=yes / skip]:
  [Capture running]  Run 'nmap SYN + TCP connect + version scans' from Kali now.
  Press ENTER when attack is complete:
```
That's your cue to switch to Kali and run the matching command, then switch back and press ENTER once it's genuinely finished (watch for the Kali shell prompt to return, not just the output slowing down — `nmap -sV` in particular keeps working quietly after the visible scan output looks done).

| Attack | Command to run on Kali |
|---|---|
| **PortScan** | `sudo nmap -sS -p 1-1024 10.0.0.20 && nmap -sT -p 1-1000 10.0.0.20 && sudo nmap -sV 10.0.0.20` |
| **SSHBruteForce** | `hydra -l labuser -P /tmp/pass.txt ssh://10.0.0.20` |
| **WebBruteForce** | `hydra 10.0.0.20 http-get-form '/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=PASTE_COOKIE_HERE; security=low:Username and/or password incorrect' -l admin -P /tmp/pass.txt` |
| **SQLInjection** | `sqlmap -u 'http://10.0.0.20/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='PHPSESSID=PASTE_COOKIE_HERE; security=low' --batch --dbs` |
| **DoSSYNFlood** | `sudo timeout -s INT 2 hping3 -S --flood -p 80 10.0.0.20` |
| **DoSUDPFlood** | `sudo timeout -s INT 2 hping3 --udp --flood -p 80 10.0.0.20` |
| **DDoSSYNFlood** | `sudo bash -c 'timeout -s INT 2 hping3 -S --flood --rand-source -p 80 10.0.0.20 & timeout -s INT 2 hping3 -S --flood --rand-source -p 443 10.0.0.20 & timeout -s INT 2 hping3 -S --flood --rand-source -p 22 10.0.0.20 & wait'` |

Notes on the table above:
- **Fresh `PHPSESSID` every time** — grab it right before WebBruteForce and again right before SQLInjection (log into DVWA, dev tools → cookies). A stale one causes DVWA to redirect every request to the login page, which makes hydra/sqlmap look like they're 100% succeeding (every attempt "succeeds" because the failure string never appears) while actually testing nothing.
- **DDoSSYNFlood is wrapped in a single `sudo bash -c '...'`**, not three separate `sudo ... &` commands — backgrounding three separate `sudo` calls simultaneously means each needs its own password prompt but none can actually read your input, so they all suspend on "tty input." A single outer `sudo` avoids this entirely.
- **`timeout -s INT 2`, not `-c <count>`** — `hping3 --flood` silently ignores `-c` (packet count) entirely; flood mode strips out that bookkeeping for maximum raw speed and never self-terminates on its own. Bounding it by *time* instead is the only way to make it stop automatically. `-s INT` matches Ctrl+C's signal so `hping3` still prints its clean summary stats instead of being abruptly killed.

**Before you start on Kali**, make sure `/tmp/pass.txt` exists with real passwords (§2.5) and you're logged into DVWA with Security = Low in a browser (for cookie-grabbing).

### Automated Execution

`--auto` mode skips the manual Kali step by running each phase's attack command as a **local subprocess on whichever machine is running `run_experiment.py`** — it does not SSH anywhere, despite the docstring mentioning SSH:
```bash
sudo venv/bin/python3 run_experiment.py \
    --interface ens33 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.20" \
    --auto \
    --phpsessid "your_dvwa_cookie"
```
For this to actually reproduce the two-VM design, `nmap`/`hydra`/`sqlmap`/`hping3` would need installing **on the Victim itself**, and the traffic would be self-targeted rather than arriving from a distinct attacker IP — which changes what your capture proves. Treat `--auto` as a smoke-test convenience, not how you generate your real dataset; use interactive mode with a real Kali VM for that.

### Standalone Targeted Captures

For a single event instead of the whole pipeline:

```bash
# Just a ping
sudo python3 capture_benign.py --interface ens33 --extra-filter "icmp and host 10.0.0.10"

# Just a port scan
sudo python3 capture_portscan.py --interface ens33 --extra-filter "host 10.0.0.10"

# A DoS attack (SYN flood by default, auto-stops after 2s; --type udp for UDP)
sudo python3 capture_dos.py --interface ens33 --outdir /home/ubuntu/captures --extra-filter "host 10.0.0.10"

# A DDoS attack (multi-source spoofed SYN flood, each stream auto-stops after 2s)
# NOTE: --rand-source spoofs the source, so "host <attacker_ip>" won't work here.
sudo python3 capture_ddos.py --interface ens33 --outdir /home/ubuntu/captures --extra-filter "dst host 10.0.0.20 and tcp"
```
`capture_ddos.py` is also the tool to redo just the DDoS phase if a full-pipeline run lost it to the filter issue above, without re-running everything else.

### Pipeline Phases Explained

| Phase | Description | Output |
|-------|-------------|--------|
| **Phase 3: Benign** | Generates baseline background traffic. Manually browse the web app, ping, SSH in, while this runs. | `BENIGN_<ts>.pcap` |
| **Phase 4: Attacks** | Captures each attack individually: PortScan, SSHBruteForce, WebBruteForce, SQLInjection, DoSSYNFlood, DoSUDPFlood, DDoSSYNFlood. | `<Attack>_<ts>.pcap` |
| **Phase 5: Verification** | Cross-references pcaps with `labels.log`, applying heuristic thresholds to prove attack traffic exists. | `verification_table.md` |
| **Phase 7: Extraction** | Parses all pcaps, aggregates bidirectional flows, computes ML features, applies ground-truth labels. | `ids_dataset.csv` |

### Full CLI Reference (`run_experiment.py`)

| Flag | Default | Purpose |
|---|---|---|
| `--interface`, `-i` | *(none — lists interfaces and exits)* | Capture interface, e.g. `ens33`. Not required for `--verify-only`/`--extract-only`, which never touch the network. |
| `--attacker-ip` | `10.0.0.10` | Kali's IP — used for filtering and flow labelling |
| `--victim-ip` | `10.0.0.20` | Victim's IP — used to build `--auto` attack commands, and as a labelling fallback for spoofed-source attacks (§4) |
| `--outdir` | `/home/ubuntu/captures` | Where pcaps, `labels.log`, and CSVs are written |
| `--benign-duration` | `0` (wait for ENTER) | Seconds to capture Phase 3 benign traffic; `0` prompts you to stop manually |
| `--extra-filter` | *(none)* | BPF capture filter applied to every capture, e.g. `"host 10.0.0.20"` |
| `--auto` | off | Run attack commands automatically instead of prompting — see caveats above |
| `--phpsessid` | `changeme` | DVWA session cookie substituted into the WebBruteForce/SQLInjection `--auto` commands |
| `--skip-benign` | off | Skip Phase 3 entirely |
| `--skip-attacks` | off | Skip Phase 4 entirely |
| `--skip-verify` | off | Skip Phase 5 entirely |
| `--skip-extract` | off | Skip Phase 7 entirely |
| `--verify-only` | off | Run **only** Phase 5 against pcaps already in `--outdir` — no `--interface` needed |
| `--extract-only` | off | Run **only** Phase 7 against pcaps already in `--outdir` — no `--interface` needed |

`--skip-*` and `--verify-only`/`--extract-only` are the fast path when iterating on extraction/verification logic — no need to re-run the whole attack sequence every time.

---

## 4. How Everything Works (Module Breakdown)

### `ids_capture/capture.py` (The Sniffer Engine)
Provides the `CaptureSession` context manager. Boots `dumpcap` as a subprocess, prints a live `[monitor]` line every 2s showing elapsed time and captured size, and logs exact start/stop UTC timestamps to `labels.log`.

### `ids_capture/labels.py` (The Ground-Truth Engine)
Parses `labels.log` into `LabelWindow` objects. `label_flows()` labels a flow with an attack name if **both**: (1) its timestamp falls inside that attack's `[start, stop]` window, and (2) `src_ip` or `dst_ip` matches `attacker_ip` **or** `victim_ip`. The `victim_ip` fallback matters specifically for spoofed-source attacks (`DDoSSYNFlood`'s `--rand-source`) — without it, a flow whose source is a randomized fake IP never matches `attacker_ip` on either side and silently falls through to `BENIGN` despite being squarely inside the attack window. This was confirmed live: an early run produced 415K genuine DDoS flow rows, all mislabeled `BENIGN`, with no `DDoSSYNFlood` label appearing anywhere in the dataset. Matching on the victim instead is safe because each labelled window is attack-only — no concurrent benign traffic is generated during it.

### `ids_capture/extract_flows.py` (The Feature Engineer)
Parses `.pcap` files via `tshark -T fields` with memory-efficient stream processing and multi-threaded parallelism across pcaps. Groups packets into 5-tuple bidirectional flows (default 120s inactivity timeout), computing:
* **Time-based:** Duration, Inter-Arrival Time (Mean, Std, Max, Min)
* **Volume-based:** Total Packets, Total Bytes, Packets/sec, Bytes/sec
* **Behavioral:** TCP Flag counts (SYN, ACK, RST, FIN, PSH, URG), Mean Window Size

### `ids_capture/verify.py` & `verify_report.py` (The Evidence Generator)
Runs a single-pass `tshark` query per pcap, counting SYN-only packets, unique destination ports, SSH packets, HTTP requests, and SQLi keywords, then applies label-specific thresholds (`_auto_verify()`) to mark each pcap `✓ YES`/`✗ NO`. Thresholds are scaled for a smaller-scope project (short wordlist, brief attack windows) rather than a full dissertation-scale run — tune `_auto_verify()` if your attack volume differs significantly.

One thing worth knowing if you're reading tshark output directly elsewhere: boolean fields (`tcp.flags.syn`, `http.request`, etc.) render as the literal strings `"True"`/`"False"` on some tshark builds and `"1"`/`"0"` on others — `verify.py`'s `_is_true()` helper accepts both; if you write your own tshark-parsing code, do the same rather than comparing against a single hardcoded value.

Standalone single-pcap report:
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

## 6. Comparing Against Suricata

Once you have a verified, labelled dataset, running it back through a real signature-based IDS gives you a second reference point — useful for a methodology/comparison chapter.

Install once (needs internet, see §2.7):
```bash
sudo apt install -y suricata
sudo suricata-update
```

Run it in offline mode against each pcap (no live interface involved — `-r` reads a file):
```bash
mkdir -p ~/captures/suricata_logs
for f in ~/captures/*.pcap; do
  name=$(basename "$f" .pcap)
  mkdir -p ~/captures/suricata_logs/"$name"
  sudo suricata -r "$f" -l ~/captures/suricata_logs/"$name" -c /etc/suricata/suricata.yaml
done
```

Two output files per pcap worth reading:
- **`fast.log`** — one line per alert, human-readable: `MM/DD/YYYY-HH:MM:SS  [**] [gid:sid:rev] MESSAGE [**] [Classification: ...] [Priority: N] {PROTO} SRC:PORT -> DST:PORT`
- **`eve.json`** — full structured JSON event log, useful if you want to programmatically cross-reference Suricata's verdicts against your own `labels.log` ground truth.

**An empty `fast.log` for some attacks is a legitimate, expected result, not a failure.** Suricata's default Emerging Threats Open ruleset is built mostly around known malware/CVE signatures, not generic behavioral detection — a plain `nmap -sS` scan or a raw `hping3` flood often produces zero alerts out of the box, since that needs rate-based (`threshold`/`detection_filter`) or scan-specific rule categories that aren't enabled by default. `SQLInjection`/`WebBruteForce` are the most likely to actually trigger something, since ET-Open includes broad HTTP-layer injection/brute-force signatures. This contrast — a signature-based IDS missing what your flow/statistical-based labels catch — is itself a valid, reportable finding.

**"Invalid checksum" in Suricata's output**: a benign artifact of NIC checksum offloading, extremely common in virtualized labs (VMware/VirtualBox/KVM all do this) and with `hping3`-crafted raw packets. The capture tool grabs the packet before hardware fills in the real checksum, so it looks "invalid" even though the packet that actually hit the wire was fine. It doesn't affect your dataset. If you want Suricata to stop flagging it, set in `/etc/suricata/suricata.yaml`:
```yaml
stream:
  checksum-validation: no
```

---

## 7. Common Pitfalls & Troubleshooting

### Environment / VM setup

| Issue | Solution |
|-------|----------|
| **VMware: "attempted to enable promiscuous mode... not allowed for security reasons"** | Host-level VMware restriction. `/dev/vmnet*` is root-only (`crw-------`) by default. On the **host**: `sudo chmod a+rw /dev/vmnet0 /dev/vmnet1 /dev/vmnet8`, then fully power-cycle the VM (guest reboot alone won't re-request it). Make it permanent (udev recreates them root-only on host reboot otherwise): `echo 'KERNEL=="vmnet[0-9]*", MODE="0666"' \| sudo tee /etc/udev/rules.d/99-vmware-vmnet.rules && sudo udevadm control --reload-rules && sudo udevadm trigger`. See §2.8-A. |
| **`dumpcap: ... could not be opened: Permission denied` when *writing* a new pcap** | Two one-time fixes, see §2.8-B: `sudo chmod 777 <outdir>` (dumpcap's own default file mode is 600; `chown` alone never touches mode bits) and `sudo chmod o+x /home/<user>` (Ubuntu often defaults new home dirs to 750, blocking traversal for `dumpcap`'s capability-limited identity even under `sudo`). Reproduce outside Python first to confirm it's not a pipeline bug: `sudo dumpcap -i <iface> -w <outdir>/test.pcap -s 0 -q -f "host <ip>"`. |
| **`tshark: You don't have permission to read the file` — even as root, even after `chown`/`chmod`** | AppArmor confining `dumpcap`/`tshark` — a separate, distinct failure from the write-side entry above. Tell: `Running as user "root" and group "root". This could be dangerous.` printed right before the denial. `sudo systemctl stop apparmor` is *not* a reliable test (profiles already loaded stay enforced). Confirm properly with `sudo aa-status` (look for `tshark`/`tshark//dumpcap` under enforce vs complain mode) and `sudo dmesg \| grep -i apparmor` for an actual `DENIED` line. Fix: `sudo aa-complain /etc/apparmor.d/usr.bin.tshark` (target the profile file directly — it's often a `tshark//dumpcap` child hat, not a standalone `/usr/bin/dumpcap` entry). See §2.8-C — in one debugging session this was suspected but `dmesg` proved it wasn't the actual cause; the home-directory traverse bit was. |
| **Permission Denied opening PCAPs (as a normal, non-sudo user afterward)** | Every file the pipeline writes is root-owned since it runs under `sudo`. `run_experiment.py` automatically hands `--outdir` back to the invoking user (via `SUDO_UID`/`SUDO_GID`) on exit — success, early exit, or crash. Only fires if the process actually ran under `sudo`; if you still hit this, check you didn't pass `--outdir ~/captures` (resolves to `/root/captures` under `sudo`, which `chmod` alone can't fix since `/root` itself blocks non-root traversal) and that the process wasn't `SIGKILL`ed (skips the cleanup) — in that case, `sudo chown -R $(whoami):$(whoami) <outdir>` manually. |
| **Wrong Interface Name** | Don't assume `eth0`. VirtualBox uses `enp0s3`, VMware uses `ens33`. Run `ip a` or the script with no `--interface` to list valid names. |
| **Clock Drift** | If pcap timestamps don't match `labels.log`, VM clocks are drifting — install VirtualBox Guest Additions / VMware Tools on both VMs to sync with the host. |
| **Internet Leakage into BENIGN traffic** | VM is exposed to the real internet. Set the hypervisor network adapter to Host-only/Internal, not NAT/Bridged (see §2.1). |
| **A specific site (e.g. GitHub) times out, others work fine** | Not a VM issue — router/ISP-level filtering or host security software. See §2.7 for how to confirm and work around it. |

### Attack commands (Kali-side)

| Issue | Solution |
|-------|----------|
| **Hydra: "optional parameters must have the format X=value" / "no valid optional parameter type given: F"** | The real `http-get-form` syntax (confirmed via `hydra -U http-get-form`) is `<url>:<form parameters>[:<optional>[:<optional>]]:<condition string>` — the condition string is the **last** field, not the third. `H=`/`C=`/etc. go *before* it. The condition is a bare string by default (meaning "failure"); `F=` is never valid anywhere (only `S=` exists, for success), and putting anything in the optional-parameter slot must be one of `1, M, c, C, g, G, h, H`. Any literal colon inside an optional value (the `Cookie: PHPSESSID=...` header) must be escaped `\:`. Use the corrected command from §3's table. |
| **Hydra reports every password "valid" (e.g. "5 of 5 found")** | False positive: the failure string never appeared in the response, so hydra treats *absence of failure* as success. Re-run with `-d` and look for `[DEBUG] attempt result: found 0, redirect 1, location: ../../login.php` — means DVWA redirected every request to login before reaching the brute-force form, i.e. `PHPSESSID` isn't authenticated. Common causes: a stray character stuck onto the cookie from copy/paste (check the `[DATA] attacking ...` line in `-d` output for the exact string hydra sent), or a stale session (repeated failed runs can invalidate it — grab a fresh cookie right before each attempt). |
| **hping3 `--flood` runs forever / ignores `-c`** | Real `hping3` behavior: `-c` is silently ignored whenever `--flood` is used (flood mode strips the counting bookkeeping for max speed). Bound it by time instead: `timeout -s INT <seconds> hping3 ...` — `-s INT` matches Ctrl+C's signal so it still prints its clean summary. See §3's table for the exact commands, all pre-wrapped this way. |
| **Backgrounded `sudo hping3 ... &` commands "suspended (tty input)"** | Each backgrounded `sudo` needs its own password prompt but can't read your input while backgrounded, so they all suspend. Wrap the whole thing in one outer `sudo bash -c '...'` instead — only one password prompt, and the inner commands inherit root without calling `sudo` themselves. See the DDoSSYNFlood row in §3's table. |
| **DDoSSYNFlood capture is 0 bytes despite hping3 showing real traffic sent** | `--rand-source` spoofs the source IP, so an attacker-centered `--extra-filter "host <attacker_ip>"` matches nothing during that phase. Use `"host <victim_ip>"` for the whole pipeline instead (§3's golden path already does this) — matches every phase including DDoS, since all attack traffic is destined to the Victim regardless of claimed source. Lost a capture to this already? Redo just that attack: `capture_ddos.py --extra-filter "dst host <victim_ip> and tcp"`. |
| **Hydra/sqlmap "failing" (0 hits in verification)** | Only passes if the credential in `/tmp/pass.txt` is actually correct — a failed brute-force still generates traffic, but `verify.py` keys off request/packet counts, not login success. Confirm DVWA Security = Low, you're attacking `/vulnerabilities/brute/`, and the `PHPSESSID` is current. |

### Verification & extraction

| Issue | Solution |
|-------|----------|
| **tshark fails with a specific exit code during Phase 5/7** | `extract_flows.py`/`verify.py` include tshark's own `stderr` in the warning, not just the bare code. **3** = "isn't a capture file in a format TShark understands" (corrupt/garbled header, not just cut short). **14** = "cut short in the middle of a packet" (genuinely truncated, e.g. an unclean kill). `file <pcap>` / `capinfos <pcap>` to inspect directly. |
| **DDoS (or other spoofed-source) flows end up labeled `BENIGN` instead of the attack name** | See §4's `labels.py` explanation — `label_flows()` needs the `victim_ip` fallback for any attack that spoofs its source, since neither side of the flow ever matches `attacker_ip`. Fixed as of this version; if you're on an older copy of this code, re-run `--extract-only` after updating. |
| **`SYN-only pkts`/`HTTP requests` always show 0 in verification, even for obviously SYN-heavy or HTTP-heavy captures** | tshark on some builds renders boolean fields (`tcp.flags.syn`, `http.request`) as `"True"`/`"False"` rather than `"1"`/`"0"` — `verify.py` used to only ever compare against `"1"`. Fixed via `_is_true()` (§4); if counts are still stuck at zero, confirm directly: `tshark -r <pcap> -n -T fields -E separator=$'\t' -E header=n -e frame.number -e ip.src -e tcp.flags.syn -e tcp.flags.ack -e tcp.dstport \| head -10` and check what your build actually outputs. |
| **`WebBruteForce`/`SQLInjection` verified `✗ NO` despite real evidence (SQLi keyword found, real SYN traffic)** | Thresholds in `_auto_verify()` are calibrated for a small wordlist / brief attack window already (§4) — if you're still hitting this, the attack generated even less HTTP volume than that. Either lower the relevant threshold further in `ids_capture/verify.py`, or generate more traffic (longer wordlist, more sqlmap probing). |
| **Missing Flow Labels (everything comes out `BENIGN`)** | Wrong `--attacker-ip` — if it doesn't match Kali's actual IP, `labels.py` never matches on the attacker side (the victim-IP fallback still catches spoofed-source attacks, but a plain IP typo breaks everything else). |

---
