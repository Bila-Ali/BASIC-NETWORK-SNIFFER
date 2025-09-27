README.txt
==========

Sniffer (Scapy) — Simple packet sniffing example
-----------------------------------------------

Description:
A small Python script using Scapy to capture packets on a specified network interface and print basic info:
- IPv4 source/destination and protocol
- TCP/UDP source and destination ports (when present)

Files:
- `sniff.py` (or whatever you name your script) — main sniffing code using Scapy

-------------------------------------------------------------------------------
Requirements
-------------------------------------------------------------------------------
- Python 3.8+ (works with 3.7 in many environments but 3.8+ recommended)
- Scapy Python library

Install Scapy:
```bash
python3 -m pip install --user scapy
