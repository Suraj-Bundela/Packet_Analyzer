from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp, get_if_addr
import socket
from scapy.layers.dns import DNS, DNSRR
from scapy.all import IFACES
dns_cache = {}
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
packet_filter_ip = None
host_cache = {}
selected_interface = None

def get_network_range():

    ip = get_if_addr(selected_interface)

    print("Interface IP:", ip)

    parts = ip.split(".")

    return ".".join(parts[:3]) + ".0/24"

def get_interfaces():

    interfaces = []

    for iface in IFACES.values():

        try:

            interfaces.append(
                iface.name
            )

        except:
            pass

    return interfaces


def set_interface(iface):

    global selected_interface

    selected_interface = iface

    print(
        f"Selected Interface: {iface}"
    )


def get_hostname(ip):

    if ip in host_cache:
        return host_cache[ip]

    try:
        hostname = socket.gethostbyaddr(ip)[0]

    except:
        hostname = ip

    host_cache[ip] = hostname

    return hostname

def analyze_packet(packet, gui_callback):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global packet_filter_ip

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if packet.haslayer(DNSRR):

        try:

            dns_name = packet[DNSRR].rrname.decode().rstrip(".")
            dns_ip = packet[DNSRR].rdata

            if isinstance(dns_ip, str):

                dns_cache[dns_ip] = dns_name

                print(
                    f"DNS Cached: {dns_name} -> {dns_ip}"
                )

        except Exception as e:
            print(e)
    
    dst_host = dns_cache.get(
    dst_ip,
    get_hostname(dst_ip)
    )
    if dst_ip in dns_cache:
        print(
            f"Using DNS cache: {dst_ip} -> {dns_cache[dst_ip]}"
        )

    # Apply filter only if one exists
    if packet_filter_ip:

        if (
            src_ip != packet_filter_ip
            and dst_ip != packet_filter_ip
        ):
            return

    packet_count += 1

    protocol = "Other"
    src_port = "-"
    dst_port = "-"

    if packet.haslayer(TCP):
        protocol = "TCP"
        tcp_count += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        udp_count += 1
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp_count += 1

    length = len(packet)

    gui_callback(
        packet_count,
        src_ip,
        dst_ip,
        dst_host,
        protocol,
        src_port,
        dst_port,
        length,
        tcp_count,
        udp_count,
        icmp_count
    )


sniffing = False

def start_sniffing(gui_callback):

    global sniffing
    sniffing = True

    sniff(
    prn=lambda packet: analyze_packet(packet, gui_callback),
    store=False,
    iface=selected_interface,
    stop_filter=lambda x: not sniffing
    )


def stop_sniffing():

    global sniffing
    sniffing = False


def set_filter(ip):

    global packet_filter_ip

    if ip.strip() == "":
        packet_filter_ip = None
    else:
        packet_filter_ip = ip.strip()


def clear_filter():
    global packet_filter_ip
    packet_filter_ip = None

# NETWORK DEVICE SCANNER
def scan_network():

    # Get current IP
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    # Build network automatically
    network_range = get_network_range()

    print("Local IP:", local_ip)
    print("Scanning:", network_range)

    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(
    packet,
    timeout=5,
    verbose=False,
    iface=selected_interface
    )[0]

    print("Results:", len(result))

    devices = []

    for sent, received in result:

        print(received.psrc, received.hwsrc)

        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices