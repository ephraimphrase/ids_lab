# IDS Packet Capture & Analysis Suite

A packet-level data collection pipeline for the MSc dissertation:
**"A Packet-Level Intrusion Detection System — Lab Setup to Dataset Generation to Automated Threat Verification"**

## 1. What This Project Does

You run two virtual machines: a **Victim** (Ubuntu, running a deliberately vulnerable website) and an **Attacker** (Kali Linux). You launch real attacks — port scans, brute-force logins, SQL injection, denial-of-service floods — from the Attacker against the Victim. This project captures every packet of that traffic on the Victim, proves each attack actually happened, and turns the raw packets into a labelled dataset you can feed into a machine learning model.

Three design choices worth knowing before you start, because they explain some of the setup steps below:

- **Packets are captured with `dumpcap`** (Wireshark's capture engine), not a Python script, because Python is too slow to keep up with a real flood attack without dropping packets.
- **Flow features are computed with `tshark`**, not the CICFlowMeter tool most IDS papers use, because CICFlowMeter is unmaintained and hard to build. This project replicates its feature set in Python you can actually read and defend.
- **Every attack is automatically verified** — the pipeline counts SYN packets, scanned ports, HTTP requests, etc. in each capture and checks they match what that attack should look like, so you have evidence the attack really happened, not just a filename that says so.

## 2. What You Need Before Starting

- VMware (Workstation or Player) installed on your computer (the **host**).
- Two virtual machines already created:
  - **Victim**: Ubuntu Server or Desktop.
  - **Attacker**: Kali Linux.
- Both VMs can currently reach the internet. (You will lock this down to an isolated, internet-free network later — not yet. Doing it too early is the single most common setup mistake: several steps below need to download things, and an isolated network has no route to the internet.)

Two IP addresses are used as examples throughout this guide:
- Victim: `10.0.0.20`
- Attacker (Kali): `10.0.0.10`

If you use different addresses, substitute your own everywhere you see these.

---

## 3. Setting Up the Victim VM

Do these steps **in this exact order**. Steps 3.1–3.6 need internet access; step 3.7 removes it. If you do 3.7 first, every later step will fail with confusing connection errors.

### 3.1 Install the required packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tshark wireshark-common tcpdump python3-pip python3-venv git openssh-server docker.io
```

- `tshark`/`wireshark-common`/`tcpdump` — the packet capture and analysis engines this project wraps.
- `python3-venv`/`python3-pip` — for running this project's Python code in an isolated environment.
- `git` — to download this project's code (or skip this if you'll transfer the files another way).
- `openssh-server` — Ubuntu Desktop doesn't include this by default, and one of the attacks (SSH brute force) needs a running SSH server to attack.
- `docker.io` — used in the next step to run the practice website with almost no manual configuration.

If `wireshark-common` asks *"Should non-superusers be able to capture packets?"* — either answer is fine; every command in this project runs with `sudo` anyway.

Start Docker:
```bash
sudo systemctl enable --now docker
```

### 3.2 Start the practice website (DVWA)

DVWA (Damn Vulnerable Web Application) is the deliberately insecure website the attacks target. Running it as a Docker container is far simpler than installing it manually — everything it needs (web server, PHP, database) is bundled inside the container.

```bash
sudo docker run -d --name dvwa -p 80:80 --restart unless-stopped vulnerables/web-dvwa
```

Now open a browser (on the Victim VM, or from your host if networking allows it at this point) and go to the Victim's current IP address:

1. Visit `http://<victim-ip>/setup.php` and click **Create / Reset Database**.
2. Log in with the default account: username `admin`, password `password`.
3. In the navigation menu, click **DVWA Security** and set it to **Low**. Every attack command in this guide assumes this setting.

If you ever need to start over: `sudo docker rm -f dvwa`, then repeat the `docker run` command above.

### 3.3 Create the account the SSH attack will target

One of the attacks is a brute-force SSH login attempt. It needs a real account to attack, with a password you know:

```bash
sudo useradd -m -s /bin/bash labuser
sudo passwd labuser
```

`sudo passwd labuser` will ask you to type a password twice. **Write it down** — you'll need to put this exact password into a file on the Attacker VM later, or the attack will run but never actually succeed.

The username must be exactly `labuser` — it's hardcoded into this project's attack commands.

Confirm SSH will accept password logins:
```bash
sudo grep -i passwordauthentication /etc/ssh/sshd_config
```
This should print a line ending in `yes`. If it says `no`, open the file with `sudo nano /etc/ssh/sshd_config`, change that line to `PasswordAuthentication yes`, save, and run `sudo systemctl restart ssh`.

### 3.4 Turn off things that would block the attacks

Two Ubuntu security features exist specifically to stop the kind of traffic you're about to generate on purpose. Turn them off for this lab machine:

```bash
sudo systemctl stop fail2ban 2>/dev/null
sudo systemctl disable fail2ban 2>/dev/null
sudo ufw disable
```

`fail2ban` automatically bans an IP address after repeated failed login attempts — which is exactly what the SSH brute-force attack does, so without this it will ban the Attacker VM partway through and the attack will look like it failed even when the password was correct.

### 3.5 Get this project's code and set up Python

```bash
git clone https://github.com/ephraimphrase/ids_lab.git ~/ids_lab
cd ~/ids_lab
python3 -m venv venv
source venv/bin/activate
pip install pandas
```

If GitHub isn't reachable on your network, transfer the project files to the VM some other way (a USB drive, a file share, a different download mirror) — everything after this step works the same regardless of how the files got there.

**One important thing to remember for the rest of this guide**: this project's scripts need `sudo` (root) to capture packets, but `sudo` starts a completely fresh process that does **not** know about the Python environment you just activated — even though your terminal prompt still shows `(venv)`. If you run `sudo python3 run_experiment.py`, it will fail with `ModuleNotFoundError: No module named 'pandas'`, because it's silently using a different, plain Python install instead of the one you just set up.

The fix is to always tell `sudo` exactly which Python to use, by its full path inside the project folder:

```bash
sudo venv/bin/python3 run_experiment.py ...
```

Every command in this guide that runs `run_experiment.py` uses this pattern. Don't shorten it to `sudo python3 run_experiment.py` — it will run, but silently using the wrong Python.

### 3.6 Install Suricata

Suricata is a separate, real intrusion detection tool. You'll run it at the very end, after your dataset exists, to compare its results against your own. Install it now, while you still have internet:

```bash
sudo apt install -y suricata
sudo suricata-update
```

The second command downloads a set of detection rules and needs internet access on its own, separate from the `apt install`.

### 3.7 Now, lock down the network

Everything above needed internet access. Nothing from this point forward does. This is the step that isolates the Victim and Attacker VMs from each other and from the outside world, and gives the Victim a fixed IP address that won't change.

**In VMware** (on your host machine, not inside the VM): open **Edit → Virtual Network Editor**, or right-click the VM and go to **Settings → Network Adapter**, and set the adapter to **Host-only** (or a custom network shared only between the Victim and Attacker VMs). Do this for both VMs. Avoid NAT or Bridged for this — those give the VM a route back to the real internet, which will pollute your "normal traffic" capture later with random background noise.

**Now set a fixed IP address inside the Victim VM.** Find your netplan configuration file — it's usually named `00-installer-config.yaml`:
```bash
ls /etc/netplan/
sudo nano /etc/netplan/00-installer-config.yaml
```

Replace its contents with (keep your interface's real MAC address, shown by `ip a`, in place of the example one below):
```yaml
network:
  ethernets:
    ens33:
      addresses: [10.0.0.20/24]
      dhcp4: false
      dhcp6: false
      match:
        macaddress: 00:0c:29:xx:xx:xx
      set-name: ens33
  version: 2
```

Apply it and confirm:
```bash
sudo netplan apply
ip a show ens33
```
You should see `10.0.0.20/24` in the output. There is deliberately no internet gateway in this configuration — you no longer need one, and having one risks leaking outside traffic into your captures.

If `netplan apply` prints a permissions warning, run `sudo chmod 600 /etc/netplan/00-installer-config.yaml` and try again.

---

## 4. Setting Up the Attacker (Kali) VM

Kali needs no package installs — `nmap`, `hydra`, `sqlmap`, and `hping3` are already included. So there's no internet-access ordering concern here; do these two steps in either order.

### 4.1 Set a fixed IP address

Kali doesn't use netplan — it uses a tool called NetworkManager instead.

```bash
ip a
nmcli connection show
```
The second command lists your active network connection's name (commonly `Wired connection 1`). Then:
```bash
sudo nmcli connection modify "Wired connection 1" ipv4.addresses 10.0.0.10/24
sudo nmcli connection modify "Wired connection 1" ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```
Confirm: `ip a` should now show `10.0.0.10/24`.

### 4.2 Create the password list

The brute-force attacks need a file listing candidate passwords, including the real ones, or they'll generate traffic but never actually succeed:

```bash
cat > /tmp/pass.txt << 'EOF'
123456
password
admin
YOUR_ACTUAL_LABUSER_SSH_PASSWORD
EOF
```
Replace the last line with the real password you set for `labuser` back in step 3.3. Put it near the top of the list — the SSH and web brute-force attacks only run for a short time, and a long list might not reach the correct password before time runs out.

---

## 5. Fixing Three Known VM Quirks

These three issues are specific to running this kind of packet-capture project inside VMware and Ubuntu. They don't always happen, but when they do, they all look the same from the outside — "0 bytes captured" or "permission denied" — so it's worth fixing all three now rather than debugging them one at a time later.

### 5.1 VMware blocks "promiscuous mode"

**Symptom**: a popup saying *"The virtual machine's operating system has attempted to enable promiscuous mode on Ethernet0. This is not allowed for security reasons."*

This is VMware itself (on the host) refusing a security-sensitive request. Fix it on the **host machine**, not inside the VM:
```bash
ls -la /dev/vmnet*
sudo chmod a+rw /dev/vmnet0 /dev/vmnet1 /dev/vmnet8
```
Then fully power off the Victim VM (not just restart it inside the guest) and power it back on.

This resets the next time you restart your host computer. Make it permanent:
```bash
echo 'KERNEL=="vmnet[0-9]*", MODE="0666"' | sudo tee /etc/udev/rules.d/99-vmware-vmnet.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 5.2 A file permission issue blocks saving captures

**Symptom**: `dumpcap: The file to which the capture would be saved ("...") could not be opened: Permission denied.`

Two commands fix this, run once inside the Victim VM:
```bash
mkdir -p ~/captures
sudo chmod 777 ~/captures
sudo chmod o+x /home/$(whoami)
```

Why this happens: `dumpcap` runs with special limited permissions even when started with `sudo` — it isn't quite "full root" in the way you'd expect. So it needs the capture folder, and every folder above it, to explicitly allow access, rather than relying on `sudo` to override normal file permission rules. This project's own scripts fix the `captures` folder's permissions automatically after each run, but a brand-new folder (or your home folder's own default permissions) still needs this done once by hand.

### 5.3 AppArmor blocks reading captures

**Symptom**: `tshark: You don't have permission to read the file "..."`, together with a line saying `Running as user "root" and group "root". This could be dangerous.`

This is a different problem from 5.2 — it happens when *reading* an existing capture, not when *writing* a new one. It's caused by AppArmor, a Linux security tool that can restrict which files a program is allowed to touch, separately from normal file permissions.

Check whether it's actually active:
```bash
sudo apt install -y apparmor-utils
sudo aa-status
```
Look through the output for `tshark` — it will be listed under either "profiles are in enforce mode" (this is blocking you) or "profiles are in complain mode" (this is not the problem).

If it's enforcing, relax it:
```bash
ls /etc/apparmor.d/ | grep -i tshark
sudo aa-complain /etc/apparmor.d/usr.bin.tshark
```
(Use the exact filename the `ls` command shows you, in case it's different.)

---

## 6. Checking Everything Before You Begin

Go through this list before running your first real attack. Every item should be true:

- [ ] `ping 10.0.0.20` from Kali works, and `ping 10.0.0.10` from the Victim works.
- [ ] A browser on the Victim can load `http://10.0.0.20/login.php` (DVWA's login page).
- [ ] DVWA's Security level is set to **Low**.
- [ ] From Kali, `ssh labuser@10.0.0.20` logs in successfully using the password you wrote down.
- [ ] `fail2ban` is stopped and `ufw` is disabled on the Victim.
- [ ] The three fixes in Section 5 have been applied.
- [ ] `/tmp/pass.txt` on Kali contains the real `labuser` password.

---

## 7. Running the Full Pipeline

On the Victim VM, this one command runs the entire process — generating normal traffic, running every attack, verifying it, and building the final dataset:

```bash
sudo venv/bin/python3 run_experiment.py \
    --interface ens33 \
    --attacker-ip 10.0.0.10 \
    --victim-ip 10.0.0.20 \
    --extra-filter "host 10.0.0.20" \
    --outdir /home/ubuntu/captures
```

A few things about this command worth understanding, not just copying:

- **`--interface`** is the network adapter name. VMware usually calls it `ens33`; VirtualBox usually calls it `enp0s3`. Run `ip a` on the Victim if you're not sure, or run the command above without `--interface` at all — it will print every available interface name and stop, instead of guessing wrong.
- **`--extra-filter "host 10.0.0.20"`** tells the capture tool to record only traffic involving the Victim's own IP address. Use the **Victim's** IP here, not the Attacker's — one of the attacks (the DDoS flood) deliberately fakes its source address, so filtering by the Attacker's IP would miss it entirely, while filtering by the Victim always works, since every attack is, by definition, aimed at the Victim.

The script will pause at several points and print an instruction telling you exactly what to do next — usually "switch to Kali and run this attack." Section 8 below lists the exact command for each one.

**Don't press ENTER to move on until the attack command has genuinely finished** on Kali — watch for the Kali terminal prompt to come back, not just for the on-screen output to slow down. Some tools (especially `nmap`'s version-detection scan) keep working quietly for a while after the visible output looks finished.

---

## 8. The Attack Commands

Run these on **Kali**, one at a time, only when the Victim's terminal tells you to (Section 7).

| Attack | Command to run on Kali |
|---|---|
| PortScan | `sudo nmap -sS -p 1-1024 10.0.0.20 && nmap -sT -p 1-1000 10.0.0.20 && sudo nmap -sV 10.0.0.20` |
| SSHBruteForce | `hydra -l labuser -P /tmp/pass.txt ssh://10.0.0.20` |
| WebBruteForce | `hydra 10.0.0.20 http-get-form '/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=PASTE_COOKIE_HERE; security=low:Username and/or password incorrect' -l admin -P /tmp/pass.txt` |
| SQLInjection | `sqlmap -u 'http://10.0.0.20/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='PHPSESSID=PASTE_COOKIE_HERE; security=low' --batch --dbs` |
| DoSSYNFlood | `sudo timeout -s INT 2 hping3 -S --flood -p 80 10.0.0.20` |
| DoSUDPFlood | `sudo timeout -s INT 2 hping3 --udp --flood -p 80 10.0.0.20` |
| DDoSSYNFlood | `sudo bash -c 'timeout -s INT 2 hping3 -S --flood --rand-source -p 80 10.0.0.20 & timeout -s INT 2 hping3 -S --flood --rand-source -p 443 10.0.0.20 & timeout -s INT 2 hping3 -S --flood --rand-source -p 22 10.0.0.20 & wait'` |

Notes:

- **`PASTE_COOKIE_HERE`**: before WebBruteForce and again before SQLInjection, log into DVWA in a browser, open its developer tools, find the cookie named `PHPSESSID`, and paste that exact value in place of `PASTE_COOKIE_HERE`. This value changes every time you log in, so get a fresh one right before each of these two attacks — a leftover one from earlier testing will cause every attempt to look like it "succeeded" without actually testing anything.
- **DDoSSYNFlood** is written as one long `sudo bash -c '...'` command on purpose. If you instead try to run three separate `sudo hping3 ... &` commands at once, each one will ask for your password at the same time and get stuck, because none of them can actually read your typed input while running in the background. Wrapping everything in a single `sudo` avoids that entirely.
- **`timeout -s INT 2`** in front of `hping3` makes it stop itself automatically after 2 seconds. Without it, `--flood` mode would run forever and require you to manually press Ctrl+C — `hping3` deliberately ignores its own `-c` (packet count) option whenever `--flood` is used.

---

## 9. Understanding What You Get Out

After the pipeline finishes, your output folder contains:

```text
/home/ubuntu/captures/
├── labels.log                      # exact start/stop time of every attack — the ground truth
├── BENIGN_20260623_140000.pcap     # raw captured packets, one file per phase
├── PortScan_20260623_140200.pcap
├── DoSSYNFlood_20260623_144000.pcap
├── verification_table.md           # evidence table — proof each attack really happened
├── PortScan_*_flows.csv            # per-attack flow features
└── ids_dataset.csv                 # the final, combined, labelled dataset
```

`ids_dataset.csv` is the file you load into a Jupyter notebook or ML library to train a model. `verification_table.md` is ready to paste directly into a report or dissertation as evidence.

If you want to re-check verification or re-build the dataset later without recapturing anything (for example, after a fix to this project's code), you can run just those steps:
```bash
sudo venv/bin/python3 run_experiment.py --outdir /home/ubuntu/captures --verify-only
sudo venv/bin/python3 run_experiment.py --outdir /home/ubuntu/captures --extract-only
```
Neither of these needs `--interface` — they only read files you already captured, they don't touch the network.

---

## 10. Comparing Against Suricata

This is an optional final step: running your captured traffic through Suricata, a real, independent intrusion detection tool, to see what it catches compared to your own labelled dataset.

```bash
mkdir -p ~/captures/suricata_logs
for f in ~/captures/*.pcap; do
  name=$(basename "$f" .pcap)
  mkdir -p ~/captures/suricata_logs/"$name"
  sudo suricata -r "$f" -l ~/captures/suricata_logs/"$name" -c /etc/suricata/suricata.yaml
done
```

For each pcap, check `fast.log` inside its output folder — one readable line per alert. `eve.json` in the same folder has the same information in a more detailed, machine-readable format.

**An empty `fast.log` for some attacks is a normal, expected result — not something broken.** Suricata's default rules mostly look for known malware and known vulnerabilities, not generic "someone is scanning me" or "someone is flooding me" behavior. A plain port scan or a raw flood attack often produces zero alerts with Suricata's default configuration. `SQLInjection` and `WebBruteForce` are the most likely to actually trigger something. If your dissertation compares detection methods, "Suricata missed this, but our flow-based approach caught it" is a legitimate and useful finding, not a failed test.

You may also see a warning about an "invalid checksum" somewhere in Suricata's output. This is also normal — it's a side effect of how virtual network cards handle checksums, not a sign of a real problem, and it doesn't affect your results.

---

## 11. If Something Goes Wrong

### Setup problems

**A specific website (often GitHub) won't load, but others work fine.**
This isn't a VM problem — it's your actual internet connection or router blocking that one site. Confirm with `curl -v https://github.com --max-time 10` — if it times out (rather than saying it can't find the address), and the same site fails from your host computer's normal browser too, it's outside the VM entirely. A different network (like a phone hotspot) or a VPN will get around it.

**Netplan won't apply the static IP / mentions `systemd-networkd`.**
Check `ip a show ens33` anyway — it sometimes worked despite a scary-looking warning. If it genuinely didn't, run `sudo systemctl enable --now systemd-networkd` and try `sudo netplan apply` again.

**Wrong interface name.**
Don't assume `eth0`. Run `ip a`, or run `run_experiment.py` with no `--interface` at all to see the exact list of valid names.

**Clock mismatch between capture files and the evidence log.**
Install VMware Tools (or VirtualBox Guest Additions) on both VMs to keep their clocks in sync with your host computer.

### Attack command problems

**Hydra says "optional parameters must have the format X=value" or "no valid optional parameter type given: F".**
This means the command's punctuation is slightly wrong. Copy the exact command from Section 8's table rather than typing it from memory — hydra's syntax here is unusually strict about field order.

**Hydra reports every single password as correct.**
This is a false result, not a real success. Your `PHPSESSID` cookie has expired or wasn't accepted, so DVWA is redirecting every attempt to its login page instead of actually checking the password — and hydra mistakes "no failure message appeared" for success. Get a completely fresh cookie and try again.

**`hping3 --flood` never stops on its own.**
This is expected if you didn't use the exact commands from Section 8 — `--flood` mode ignores `-c` (packet count) entirely and needs `timeout` in front of it instead to stop automatically.

**Three `sudo hping3 ...` commands running in the background all get stuck asking for a password.**
Use the single combined `sudo bash -c '...'` version of the DDoS command from Section 8, not three separate ones.

**The DDoS capture file is empty (0 bytes), even though `hping3` clearly sent a lot of traffic.**
Your capture filter was set to the Attacker's IP instead of the Victim's. The DDoS attack fakes its source address on every packet, so it never matches the Attacker's real IP — but it always genuinely targets the Victim, so filtering by the Victim's IP (as in Section 7's command) always works.

### Results look wrong problems

**tshark fails partway through verification or dataset-building, with an error code.**
The error message now includes the real reason from tshark itself. Code `3` usually means the capture file's header is corrupted, not just cut off early. Code `14` means it was genuinely cut off mid-write (for example, if the capture process was killed uncleanly). Run `file <the pcap>` to inspect it directly.

**A DDoS (or any attack that fakes its source address) shows up labelled `BENIGN` in the final dataset instead of its real attack name.**
This project now specifically accounts for attacks that fake their source address when labelling flows, matching on the Victim's IP as well as the Attacker's. If you're on an older copy of this code, update it, then re-run:
```bash
sudo venv/bin/python3 run_experiment.py --outdir /home/ubuntu/captures --extract-only
```

**"SYN-only packets" or "HTTP requests" always show as 0 in the verification results, even for attacks that obviously involve a lot of SYN packets or HTTP requests.**
Some versions of `tshark` describe these as the words `True`/`False` instead of the numbers `1`/`0`, and older code only recognised the numbers. This is fixed in the current version of this project.

**A permission-denied error appears later, when just trying to open a capture file normally (not through this project's scripts).**
Every file this project writes is owned by `root`, because it runs under `sudo`. The scripts automatically hand ownership back to your normal user account when they finish — but if the process was forcefully killed partway through, that handoff never happened. Fix it manually: `sudo chown -R $(whoami):$(whoami) <the folder>`.
