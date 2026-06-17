import tkinter as tk
from tkinter import ttk
import threading
import analyzer_core


root = tk.Tk()
root.title("Network Traffic Analyzer")
root.geometry("1000x700")


title = tk.Label(root, text="Network Traffic Analyzer", font=("Arial", 16))
title.pack(pady=10)

filter_frame = tk.Frame(root)
filter_frame.pack(pady=5)

tk.Label(
    filter_frame,
    text="Filter IP:"
).pack(side="left")

filter_entry = tk.Entry(
    filter_frame,
    width=20
)
filter_entry.pack(side="left", padx=5)

def apply_filter():

    ip = filter_entry.get().strip()

    analyzer_core.set_filter(ip)

    print("Filter Applied:", ip)


def clear_filter():

    analyzer_core.clear_filter()

    filter_entry.delete(0, tk.END)

    print("Filter Cleared")

apply_button = tk.Button(
    filter_frame,
    text="Apply Filter",
    command=apply_filter
)
apply_button.pack(side="left", padx=5)

clear_button = tk.Button(
    filter_frame,
    text="Clear Filter",
    command=clear_filter
)
clear_button.pack(side="left", padx=5)

# START PACKET CAPTURE
def start_capture():

    t = threading.Thread(
        target=analyzer_core.start_sniffing,
        args=(update_gui,)
    )

    t.daemon = True
    t.start()

def stop_capture():

    analyzer_core.stop_sniffing()

button_frame = tk.Frame(root)
button_frame.pack(pady=5)

start_button = tk.Button(
    button_frame,
    text="Start Capture",
    command=start_capture
)
start_button.pack(side="left", padx=5)

stop_button = tk.Button(
    button_frame,
    text="Stop Capture",
    command=stop_capture,
    bg="red",
    fg="white"
)
stop_button.pack(side="left", padx=5)


# DEVICE SCAN
def scan_devices():

    devices = analyzer_core.scan_network()

    print("Devices returned:", len(devices))

    for device in devices:
        print(device)

    for row in device_tree.get_children():
        device_tree.delete(row)

    for device in devices:
        device_tree.insert(
            "",
            "end",
            values=(device["ip"], device["mac"])
        )


def filter_selected_device():

    selected = device_tree.selection()

    if not selected:
        return

    item = device_tree.item(selected[0])

    ip = item["values"][0]

    filter_entry.delete(0, tk.END)
    filter_entry.insert(0, ip)

    analyzer_core.set_filter(ip)

    print("Filtering:", ip)

filter_device_button = tk.Button(
    root,
    text="Filter Selected Device",
    command=filter_selected_device
)
filter_device_button.pack(pady=5)

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