# there is no Signature Detection + White & Black list
import os
import sys
import time
from collections import defaultdict  # For managing packet count per IP
from scapy.all import sniff, IP  # For sniffing and analyzing packets
import logging
logging.basicConfig(filename='./block_ips.log', level=logging.INFO)

# THRESHOLD = 40 mean an ip will be blocked if it sends more than 40 packet per second
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")


def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            # Uncomment the next line to print the IP and packet rate
            # print(f"IP: {ip}, Packet rate: {packet_rate}")
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, Packet rate: {packet_rate}")
                # os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)
                logging.info(f"Blocking IP: {ip}, Packet rate: {packet_rate}")

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
