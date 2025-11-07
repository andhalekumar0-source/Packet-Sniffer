# packet_sniffer.py
# Educational Packet Sniffer - Prodigy Infotech Internship
# Author: Andhale Kumar
# Email: andhalekumar0@gmail.com
# NOTE: For authorized and educational use only.

from scapy.all import sniff, IP, TCP, UDP, Raw
import argparse
import csv
import datetime
import os
import sys

DEFAULT_INTERFACE = None  # None => scapy chooses
OUTPUT_PCAP = "captured_packets.pcap"
OUTPUT_CSV = "packet_log.csv"

def parse_packet(pkt):
    """Extract relevant fields from a packet."""
    info = {
        "timestamp": datetime.datetime.now().isoformat(timespec='seconds'),
        "src_ip": "",
        "dst_ip": "",
        "protocol": "",
        "src_port": "",
        "dst_port": "",
        "payload": ""
    }

    if IP in pkt:
        ip = pkt[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst

        if TCP in pkt:
            tcp = pkt[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            if Raw in pkt:
                info["payload"] = bytes(pkt[Raw]).hex()[:200]  # show as hex (limited)
        elif UDP in pkt:
            udp = pkt[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport
            if Raw in pkt:
                info["payload"] = bytes(pkt[Raw]).hex()[:200]
        else:
            info["protocol"] = ip.proto
            if Raw in pkt:
                info["payload"] = bytes(pkt[Raw]).hex()[:200]
    else:
        # Non-IP packet (e.g., ARP)
        info["protocol"] = pkt.name

    return info

def print_packet(info):
    """Nicely print packet info to console."""
    print(f"[{info['timestamp']}] {info['protocol']:4} {info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']}")
    if info["payload"]:
        print(f"    payload (hex, truncated): {info['payload']}")

def packet_callback(pkt, writer=None, pcap_writer=None):
    info = parse_packet(pkt)
    print_packet(info)
    if writer:
        writer.writerow(info)
    if pcap_writer:
        pcap_writer.write(pkt)

def main():
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer - captures and logs network packets.")
    parser.add_argument("-i", "--interface", help="Network interface to listen on (e.g., eth0, wlan0). If omitted scapy chooses.", default=DEFAULT_INTERFACE)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp and port 80')", default="")
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 for infinite)", type=int, default=0)
    parser.add_argument("--csv", help="Save CSV log (default: packet_log.csv)", action="store_true")
    parser.add_argument("--pcap", help="Save pcap file (default: captured_packets.pcap)", action="store_true")
    parser.add_argument("--limit-payload", help="Limit payload hex length characters (default 200)", type=int, default=200)

    args = parser.parse_args()

    # Permission hint
    if os.name != 'nt' and os.geteuid() != 0:
        print("Warning: On Linux/macOS this script may require root privileges (run with sudo).")
    elif os.name == 'nt':
        print("On Windows, run from an elevated Command Prompt / PowerShell.")

    csv_file = None
    csv_writer = None
    if args.csv:
        csv_file = open(OUTPUT_CSV, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_file, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "payload"])
        csv_writer.writeheader()
        print(f"CSV logging enabled: {OUTPUT_CSV}")

    pcap_writer = None
    if args.pcap:
        # scapy's wrpcap will be used by writing on each packet
        from scapy.utils import PcapWriter
        pcap_writer = PcapWriter(OUTPUT_PCAP, append=True, sync=True)
        print(f"PCAP saving enabled: {OUTPUT_PCAP}")

    try:
        print("Starting packet capture...")
        sniff_args = {}
        if args.interface:
            sniff_args["iface"] = args.interface
        if args.filter:
            sniff_args["filter"] = args.filter
        if args.count and args.count > 0:
            sniff_args["count"] = args.count

        # Wrap callback to pass writers
        sniff(prn=lambda packet: packet_callback(packet, writer=csv_writer, pcap_writer=pcap_writer), store=0, **sniff_args)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Error while capturing: {e}")
    finally:
        if csv_file:
            csv_file.close()
        if pcap_writer:
            pcap_writer.close()
        print("Exiting.")

if __name__ == "__main__":
    main()
