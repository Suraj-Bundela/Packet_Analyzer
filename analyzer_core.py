from scapy.all import sniff, IP, TCP, UDP, ICMP
import subprocess
import re

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0


def analyze_packet(packet, gui_callback):

    global packet_count, tcp_count, udp_count, icmp_count

    if packet.haslayer(IP):

        packet_count += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

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
            protocol,
            src_port,
            dst_port,
            length,
            tcp_count,
            udp_count,
            icmp_count
        )


def start_sniffing(gui_callback):

    sniff(
        prn=lambda packet: analyze_packet(packet, gui_callback),
        store=False,
        iface="Wi-Fi"
    )


# NEW DEVICE DISCOVERY METHOD
def scan_network():

    output = subprocess.check_output("arp -a", shell=True).decode()

    devices = []

    pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9\-]{17})"

    matches = re.findall(pattern, output, re.IGNORECASE)

    for ip, mac in matches:

        devices.append({
            "ip": ip,
            "mac": mac
        })

    return devices