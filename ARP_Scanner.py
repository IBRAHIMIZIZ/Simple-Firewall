#! /home/ibrahimiziz/Documents/VSCode/.venv/bin/python3
import time
import sys
import ipaddress
import netifaces
from scapy.all import arping, conf

print(r"""
  ,-.       _,---._ __  / \
 /  )    .-'       `./ /   \
(  (   ,'            `/    /|
 \  `-"             \'\   / |
  `.              ,  \ \ /  |
   /`.          ,'-`----Y   |
  (            ;        |   '
  |  ,-.    ,-'Made By: |  /
  |  | (   |IBRAHIMIZIZ | /
  )  |  \  `.___________|/
  `--'   `--'""")

print("""\nThis is a simple ARP-based network scanner that identifies active devices on your local subnet by sending ARP requests and collecting responses.\nIt uses your machine's default network interface to determine the IP range automatically and displays the IP and MAC addresses of any responsive hosts.\n""")

# Get default interface
gateways = netifaces.gateways()
# You can heck the defualt interface using "ip route show"
if netifaces.AF_INET not in gateways.get('default', {}):
    print("No default IPv4 gateway found.")
    sys.exit(1)

# netifaces.AF_INET refers to the IPv4 address family
default_interface = gateways['default'][netifaces.AF_INET][1]

# Get IP and subnet mask
interfaces = netifaces.ifaddresses(default_interface)
if netifaces.AF_INET not in interfaces or not interfaces[netifaces.AF_INET]:
    print(f"No IPv4 address assigned to {default_interface}")
    sys.exit(1)

# Returns IP, Netmask, Interface in a hashtable
ip_info = interfaces[netifaces.AF_INET][0]
ip = ip_info['addr']
netmask = ip_info['netmask']

# Get CIDR and network address
try:
    # convert from 255.255.255.0 to /24 format
    cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    interface = ipaddress.IPv4Interface(f"{ip}/{cidr}")
    network = interface.network
except Exception as e:
    print(f"Failed to calculate network info: {e}")
    sys.exit(1)

# Testing output
ip_range = str(network)
print(f"[*] Using interface: {default_interface}")
print(f"[*] Local IP: {ip}")
print(f"[*] Subnet mask: {netmask} => /{cidr}")
print(f"[*] Scanning IP range: {ip_range}")
print("[*] Starting ARP scan...\n")

# Adjust Scapy configuration for better ARP results
# Increase timeout and retry for better results
conf.verb = 0  # disable verbose mode for cleaner output
timeout = 5    # per-packet timeout
retry = 5      # number of retries

start_time = time.time()

try:
    # Send ARP broadcast and capture results
    answered, unanswered = arping(ip_range, timeout=timeout, retry=retry, iface=default_interface)
    # print(unanswered) this is a useless parameter
except PermissionError:
    print("[-] Run the script as root (ARP requires raw socket privileges).")
    sys.exit(1)
except Exception as e:
    print(f"[-] ARP scan failed: {e}")
    sys.exit(1)

end_time = time.time()

# Display results (it gives a nice output format)
if not answered:
    print("[-] No active hosts found.")
    sys.exit(0)

print(f"{'IP Address':<16}    {'MAC Address'}")
print("-" * 40)
for sent, received in answered:  # xx:xx:xx:xx:xx:xx
    print(f"{received.psrc:<16}    {received.hwsrc}")

print(f"\n[+] Total hosts found: {len(answered)}")
print(f"[+] Scan completed in {end_time - start_time:.2f} seconds.")
