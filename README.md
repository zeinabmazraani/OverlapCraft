# EECE655 Assignment 1 — Overlapping IPv4 Fragments

This project demonstrates an overlapping IPv4-fragment attack and an automated detector. It is intended only for an isolated, authorized laboratory environment.

## Project Structure

```text
EECE655_A1/
├── AI_Prompts_Outputs/
├── References/
├── Version 1/
│   ├── helper_functs/
│   ├── captures/
│   │   └── *.pcap
│   ├── attacker.py
│   ├── weak_overlap_detector_v1.py
│   ├── requirements.txt
│   └── fragments.log
└── Version 2/
    └── ...
```

`fragments.log` is created when the detector runs

## Are the Commands Different for Each Version?

The environment setup is the same for every version. The commands change only when a version uses different filenames or command-line arguments.

- Always enter the folder for the version being tested.
- Run the attacker and detector from the same version.
- Do not mix a V1 attacker with a V2 detector unless the experiment specifically requires that comparison.
- Use `python SCRIPT.py --help` to view the arguments accepted by a script.
- Update this README when the V2 filenames and arguments are finalized.

## Requirements

- Python 3
- Scapy
- Npcap on Windows for live packet capture
- Administrator or root privileges for live capture and raw-packet transmission
- Two isolated VMs are recommended:
  - Attacker VM
  - Detector/victim VM

The required Python packages are listed in:

```text
Version 1/requirements.txt
```

# Windows Instructions

## 1. Initial Setup

Open PowerShell in the repository root:

```powershell
cd "C:\path\to\EECE655_A1"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r ".\Version 1\requirements.txt"
```

The virtual environment should be created only once.

For later sessions, activate the existing environment:

```powershell
cd "C:\path\to\EECE655_A1"
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 2. Test the V1 Detector Using a PCAP

Enter the Version 1 folder:

```powershell
cd ".\Version 1"
```

Run the detector using the generated test PCAP:

```powershell
python .\weak_overlap_detector_v1.py --pcap .\captures\capture.pcap
```

Offline PCAP analysis does not require Administrator privileges.

## 3. Run the V1 Detector on Live Traffic

Open PowerShell as Administrator.

Display the interface names recognized by Scapy:

```powershell
python -c "from scapy.all import get_if_list; print(*get_if_list(), sep='\n')"
```

Then run the detector using the correct interface:

```powershell
python .\weak_overlap_detector_v1.py --interface "Ethernet"
```

Replace `Ethernet` with the interface connected to the isolated lab network.

Stop the detector using:

```text
Ctrl+C
```

## 4. Run the V1 Attacker on Windows

Use a separate attacker machine or VM.

Activate the virtual environment and enter the Version 1 folder:

```powershell
cd "C:\path\to\EECE655_A1"
.\.venv\Scripts\Activate.ps1
cd ".\Version 1"
```

View the arguments accepted by the attacker:

```powershell
python .\attacker.py --help
```

Run the attacker:

```powershell
python .\attacker.py
```

If `--help` shows required arguments, such as a destination IP address or interface, add them to the command exactly as displayed by the script.

Always start the detector before starting the attacker.

# Linux Instructions

## 1. Initial Setup

Open a terminal in the repository root:

```bash
cd /path/to/EECE655_A1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r "Version 1/requirements.txt"
```

The virtual environment should be created only once.

For later sessions:

```bash
cd /path/to/EECE655_A1
source .venv/bin/activate
```

If virtual-environment creation is unavailable on Ubuntu, Debian, or Kali:

```bash
sudo apt install python3-venv
```

## 2. Test the V1 Detector Using a PCAP

Enter the Version 1 folder:

```bash
cd "/path/to/EECE655_A1/Version 1"
```

Run the detector using the generated test PCAP:

```bash
python ./weak_overlap_detector_v1.py --pcap ./captures/v1_test.pcap
```

To test using another capture:

```bash
python ./weak_overlap_detector_v1.py --pcap ./captures/capture.pcap
```

Offline PCAP analysis does not require `sudo`.

## 3. Run the V1 Detector on Live Traffic

Find the lab interface and its IP address:

```bash
ip -br address
```

Possible interface names include:

```text
eth0
ens33
enp0s3
```

From the `Version 1` folder, run the detector using the virtual environment’s Python interpreter:

```bash
sudo ../.venv/bin/python ./weak_overlap_detector_v1.py --interface ens33
```

Replace `ens33` with the interface connected to the isolated lab network.

Use `lo` only when both programs intentionally communicate through loopback on the same machine:

```bash
sudo ../.venv/bin/python ./weak_overlap_detector_v1.py --interface lo
```

Stop the detector using:

```text
Ctrl+C
```

## 4. Run the V1 Attacker on Linux

Use a separate attacker VM.

Enter the Version 1 folder:

```bash
cd "/path/to/EECE655_A1/Version 1"
```

View the arguments accepted by the attacker:

```bash
../.venv/bin/python ./attacker.py --help
```

Run the attacker with root privileges:

```bash
sudo ../.venv/bin/python ./attacker.py
```

If `--help` shows required arguments, such as a destination IP address or interface, add them exactly as displayed by the script.

Always start the detector before starting the attacker.

# Recommended Two-VM Test Order

1. Configure both VMs on the same isolated host-only or internal virtual network.
2. Find the IP addresses of both VMs.
3. Confirm connectivity by sending a ping between the two lab IP addresses.
4. On the detector/victim VM, identify the correct network interface.
5. Start `weak_overlap_detector_v1.py` in live-interface mode.
6. On the attacker VM, run the matching `attacker.py`.
7. Target only the detector/victim VM’s lab IP address.
8. Stop the detector using `Ctrl+C` after the experiment.
9. Review the terminal alerts and `fragments.log`.

The expected traffic flow is:

```text
Attacker VM → isolated virtual network → Detector/Victim VM
```

# Logs and Expected Output

- Every observed IPv4 fragment is recorded in `fragments.log`.
- Only detected overlaps are displayed as alerts in the terminal.
- Ordinary unfragmented IPv4 packets are ignored.
- A PCAP containing no IPv4 fragments produces:

```text
Fragments processed: 0
```

- A lack of alerts means that V1 did not detect a consecutive overlap.
- A lack of alerts does not prove that the traffic contains no overlap because V1 can miss non-adjacent overlapping fragments.


# Safety

Run the attacker only against systems that you own or are explicitly authorized to test.

Keep the experiment inside an isolated VM network. Do not send crafted fragments through a university, workplace, public, or production network.

Before publishing a PCAP, verify that it does not contain:

- Credentials
- Session tokens
- Personal browsing traffic
- Private DNS history
- Sensitive payload data
- Unrelated network communications
