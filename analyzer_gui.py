import tkinter as tk
from tkinter import ttk
import threading
import analyzer_core


root = tk.Tk()
root.title("Network Traffic Analyzer")
root.geometry("1000x700")


title = tk.Label(root, text="Network Traffic Analyzer", font=("Arial", 16))
title.pack(pady=10)


# START PACKET CAPTURE
def start_capture():

    t = threading.Thread(
        target=analyzer_core.start_sniffing,
        args=(update_gui,)
    )

    t.daemon = True
    t.start()


start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.pack(pady=5)


# DEVICE SCAN
def scan_devices():

    devices = analyzer_core.scan_network()

    for row in device_tree.get_children():
        device_tree.delete(row)

    for device in devices:
        device_tree.insert("", "end", values=(device["ip"], device["mac"]))


scan_button = tk.Button(root, text="Scan Network Devices", command=scan_devices)
scan_button.pack(pady=5)


# PACKET TABLE
columns = ("id", "src", "dst", "protocol", "sport", "dport", "size")

table_frame = tk.Frame(root)
table_frame.pack(fill="both", expand=True)

tree = ttk.Treeview(table_frame, columns=columns, show="headings")

tree.heading("id", text="Packet")
tree.heading("src", text="Source IP")
tree.heading("dst", text="Destination IP")
tree.heading("protocol", text="Protocol")
tree.heading("sport", text="Src Port")
tree.heading("dport", text="Dst Port")
tree.heading("size", text="Size")

tree.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
scrollbar.pack(side="right", fill="y")

tree.configure(yscrollcommand=scrollbar.set)


# DEVICE TABLE
device_frame = tk.Frame(root)
device_frame.pack(fill="x", pady=10)

device_label = tk.Label(device_frame, text="Devices on Network", font=("Arial", 12))
device_label.pack()

device_columns = ("ip", "mac")

device_tree = ttk.Treeview(device_frame, columns=device_columns, show="headings")

device_tree.heading("ip", text="IP Address")
device_tree.heading("mac", text="MAC Address")

device_tree.pack(fill="x")


# STATISTICS PANEL
stats_frame = tk.Frame(root)
stats_frame.pack(pady=10)

tcp_label = tk.Label(stats_frame, text="TCP: 0", font=("Arial", 12))
tcp_label.pack(side="left", padx=20)

udp_label = tk.Label(stats_frame, text="UDP: 0", font=("Arial", 12))
udp_label.pack(side="left", padx=20)

icmp_label = tk.Label(stats_frame, text="ICMP: 0", font=("Arial", 12))
icmp_label.pack(side="left", padx=20)


# UPDATE GUI FROM PACKETS
def update_gui(
        packet_id,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        length,
        tcp_count,
        udp_count,
        icmp_count
):

    tree.insert(
        "",
        "end",
        values=(
            packet_id,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length
        )
    )

    tree.yview_moveto(1)

    tcp_label.config(text=f"TCP: {tcp_count}")
    udp_label.config(text=f"UDP: {udp_count}")
    icmp_label.config(text=f"ICMP: {icmp_count}")


root.mainloop()