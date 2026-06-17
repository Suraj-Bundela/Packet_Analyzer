from scapy.all import get_working_ifaces

for iface in get_working_ifaces():
    print("Name:", iface.name)
    print("Description:", iface.description)
    print()