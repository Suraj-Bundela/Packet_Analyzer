from scapy.all import ARP, Ether, srp

target = "192.168.0.0/24"

arp = ARP(pdst=target)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether / arp

result = srp(
    packet,
    timeout=5,
    verbose=True,
    iface="Wi-Fi"
)[0]

print("Devices found:", len(result))

for sent, received in result:
    print(received.psrc, received.hwsrc)