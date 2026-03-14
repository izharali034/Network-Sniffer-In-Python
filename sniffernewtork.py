import argparse
import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf

# Use Layer 3 socket (safer for Windows)
conf.L3socket

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}

ip_counter = defaultdict(int)


def analyze_packet(packet):
    stats["total"] += 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        ip_counter[src] += 1

        print("\n==============================")
        print(f"Time: {timestamp}")
        print(f"Source IP: {src}")
        print(f"Destination IP: {dst}")

        if packet.haslayer(TCP):
            stats["tcp"] += 1
            tcp = packet[TCP]

            print("Protocol: TCP")
            print(f"Source Port: {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            stats["udp"] += 1
            udp = packet[UDP]

            print("Protocol: UDP")
            print(f"Source Port: {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ICMP):
            stats["icmp"] += 1
            print("Protocol: ICMP")

        else:
            stats["other"] += 1
            print("Protocol: Other")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload preview:", payload[:40])

        print("==============================")


def print_statistics():
    print("\n========= STATISTICS =========")
    print("Total Packets:", stats["total"])
    print("TCP Packets:", stats["tcp"])
    print("UDP Packets:", stats["udp"])
    print("ICMP Packets:", stats["icmp"])
    print("Other Packets:", stats["other"])

    print("\nTop Source IPs:")

    if len(ip_counter) == 0:
        print("No packets captured.")
        return

    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:10]:
        print(f"{ip} -> {count} packets")


def show_interfaces():
    print("\nAvailable Network Interfaces:\n")

    interfaces = get_if_list()

    for i, iface in enumerate(interfaces):
        print(f"{i} : {iface}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Python Network Sniffer")

    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-c", "--count", help="Number of packets to capture", type=int, default=0)
    parser.add_argument("-f", "--filter", help="BPF filter (tcp, udp, port 80)", default="")

    args = parser.parse_args()

    show_interfaces()

    iface = args.interface

    if iface is None:
        print("No interface selected. Using default.\n")

    print("Starting Network Sniffer...")
    print("Press CTRL+C to stop\n")

    try:
        sniff(
            iface=iface,
            prn=analyze_packet,
            store=False,
            count=args.count,
            filter=args.filter
        )

    except KeyboardInterrupt:
        print("\nStopping capture...")

    except Exception as e:
        print("\nError:", e)
        print("Make sure Npcap is installed.")

    finally:
        print_statistics()


if __name__ == "__main__":
    main()