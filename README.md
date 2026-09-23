# OverlapCraft: Overlapping IP Fragmentation Attack and Detection

## Contribution*
- **Attacker code**: developed by Tamer Slim
- **Detector code**: developed by Zeinab Mazraani
* Full contribution breakdown and more detail available in the report.

## Running the Simulations
All code is organized into separate folders for each version (`Version 1`, `Version 2`, `Version 3`). To run:
- `cd` into the folder of the version you want to run, then run the scripts from there.
- **Attacker V1** takes the source and destination IPs as command-line arguments: `sudo python3 attacker.py <srcIP> <dstIP>`
- **Attacker V2 and V3** are interactive: `sudo python3 attacker.py`. Follow the prompts to select an attack mode and enter the IPs.
- **Detector** (any version):
  - `sudo python3 detector.py -i <interface>` (live capture)
  - `sudo python3 detector.py -r <pcap_file>` (analyze a saved capture)
