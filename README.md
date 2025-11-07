# Packet Sniffer 🕵️‍♂️

**Prodigy Infotech Internship — Packet Sniffer (Educational)**

**Short description:**  
An educational packet sniffer that captures network packets and displays relevant information such as timestamp, source/destination IPs, ports, protocol, and (truncated) payload hex. This is for **authorized and educational use only**.

---

## Features
- Capture live network traffic (IP/TCP/UDP and others)
- Print timestamp, source/destination IP and ports, protocol, and truncated payload (hex)
- Optional CSV logging (`packet_log.csv`) and PCAP saving (`captured_packets.pcap`)
- Support for BPF capture filters (e.g., `tcp and port 80`) and selecting interface
- Lightweight, minimal dependencies (Scapy)

---

## Requirements
- Python 3.8+
- `scapy` (install below)
- Administrator/root privileges required to capture packets on most systems.

### Install dependencies
```bash
pip install scapy
