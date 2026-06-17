import tkinter as tk
from tkinter import ttk
import threading
import analyzer_core
import json
import os
from tkinter import simpledialog
from ttkbootstrap import Style





DATA_FILE = "devices.json"

def load_data():

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)

    return {}

def save_data():

    with open(DATA_FILE, "w") as f:
        json.dump(device_data, f, indent=4)

device_data = load_data()

style = Style(theme="cyborg")
root = style.master

style.configure(
    "TButton",
    font=("Segoe UI", 11)
)

root.title("Network Traffic Analyzer")
root.geometry("1200x800")


style.configure(
    "Treeview.Heading",
    font=("Segoe UI", 10, "bold")
)


title = ttk.Label(
    root,
    text="Network Traffic Analyzer",
    font=("Segoe UI", 16, "bold")
)
title.pack(pady=5)

toolbar = ttk.Frame(root)
toolbar.pack(fill="x", padx=10, pady=5)

left_toolbar = tk.Frame(toolbar)
left_toolbar.pack(side="left")

right_toolbar = tk.Frame(toolbar)
right_toolbar.pack(side="right")

paned = tk.PanedWindow(
    root,
    orient=tk.HORIZONTAL
)

paned.pack(
    fill="both",
    expand=True
)




ttk.Label(
    right_toolbar,
    text="Filter IP:"
).pack(side="left")

filter_entry = tk.Entry(
    right_toolbar,
    width=20
)
filter_entry.pack(side="left", padx=5)

def apply_filter():

    ip = filter_entry.get().strip()

    analyzer_core.set_filter(ip)
    
    status_label.config(
    text=f"Filter applied: {ip}"
    )

    print("Filter Applied:", ip)


def clear_filter():

    status_label.config(
    text="Filter cleared"
    )
    analyzer_core.clear_filter()

    filter_entry.delete(0, tk.END)

    print("Filter Cleared")

apply_button = ttk.Button(
    right_toolbar,
    text="✓ Apply Filter",
    command=apply_filter
)
apply_button.pack(side="left", padx=5)

clear_button = ttk.Button(
    right_toolbar,
    text="✖ Clear Filter",
    command=clear_filter
)
clear_button.pack(side="left", padx=5)

# START PACKET CAPTURE
def start_capture():

    status_label.config(
    text="Capturing traffic..."
    )

    t = threading.Thread(
        target=analyzer_core.start_sniffing,
        args=(update_gui,)
    )
    
    t.daemon = True
    t.start()

def stop_capture():

    analyzer_core.stop_sniffing()

    status_label.config(
        text="Capture stopped"
    )


start_button = ttk.Button(
    left_toolbar,
    text="Start",
    command=start_capture,
    bootstyle="success"
)
start_button.pack(side="left", padx=5)

stop_button = ttk.Button(
    left_toolbar,
    text="Stop",
    command=stop_capture,
    bootstyle="danger"
)
stop_button.pack(side="left", padx=5)


# DEVICE SCAN
def scan_devices():

    devices = analyzer_core.scan_network()

    for row in device_tree.get_children():
        device_tree.delete(row)

    for device in devices:

        ip = device["ip"]
        mac = device["mac"]

        display_name = ip
        trusted = False

        if mac in device_data:

            display_name = device_data[mac].get(
                "name",
                ip
            )

            trusted = device_data[mac].get(
                "trusted",
                False
            )

        if trusted:

            device_tree.insert(
                "",
                "end",
                values=(display_name, ip, mac),
                tags=("trusted",)
            )

        else:

            device_tree.insert(
                "",
                "end",
                values=(display_name, ip, mac)
            )
    status_label.config(
    text=f"Found {len(devices)} devices"
    )


def filter_selected_device():

    selected = device_tree.selection()

    if not selected:
        return

    item = device_tree.item(selected[0])

    ip = item["values"][1]


    filter_entry.delete(0, tk.END)
    filter_entry.insert(0, ip)

    analyzer_core.set_filter(ip)

    print("Filtering:", ip)

scan_button = ttk.Button(left_toolbar, text="Scan", command=scan_devices, bootstyle="info")
scan_button.pack(side="left", padx=5)



# PACKET TABLE
columns = ("id", "src", "dst", "protocol", "sport", "dport", "size")

table_frame = tk.Frame(root)

tree = ttk.Treeview(table_frame, columns=columns, show="headings")

tree.heading("id", text="Packet")
tree.heading("src", text="Source IP")
tree.heading("dst", text="Destination IP")
tree.heading("protocol", text="Protocol")
tree.heading("sport", text="Src Port")
tree.heading("dport", text="Dst Port")
tree.heading("size", text="Size")

tree.tag_configure("TCP", foreground="#0066cc")
tree.tag_configure("UDP", foreground="#008000")
tree.tag_configure("ICMP", foreground="#cc0000")
tree.tag_configure(
    "even",
    background="#202020"
)

tree.tag_configure(
    "odd",
    background="#181818"
)

tree.column("id", width=60)
tree.column("src", width=150)
tree.column("dst", width=150)
tree.column("protocol", width=80)
tree.column("sport", width=80)
tree.column("dport", width=80)
tree.column("size", width=70)

tree.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
scrollbar.pack(side="right", fill="y")

tree.configure(yscrollcommand=scrollbar.set)

def rename_device():

    selected = device_tree.selection()

    if not selected:
        return

    item = device_tree.item(selected[0])

    mac = item["values"][2]

    new_name = simpledialog.askstring(
        "Rename Device",
        "Enter device name:"
    )

    if not new_name:
        return

    if mac not in device_data:
        device_data[mac] = {}

    device_data[mac]["name"] = new_name

    save_data()

    current_ip = item["values"][1]

    device_tree.item(
    selected[0],
    values=(new_name, current_ip, mac)
    )

def add_trusted():

    selected = device_tree.selection()

    if not selected:
        return

    item = device_tree.item(selected[0])

    mac = item["values"][2]

    if mac not in device_data:
        device_data[mac] = {}

    device_data[mac]["trusted"] = True

    save_data()

    device_tree.item(
        selected[0],
        tags=("trusted",)
    )

def remove_trusted():

    selected = device_tree.selection()

    if not selected:
        return

    item = device_tree.item(selected[0])

    mac = item["values"][2]

    if mac in device_data:
        device_data[mac]["trusted"] = False

    save_data()

    device_tree.item(
        selected[0],
        tags=()
    )


# DEVICE TABLE
device_frame = tk.Frame(root)
paned.add(device_frame)
paned.add(table_frame)
paned.paneconfigure(
    device_frame,
    minsize=250
)

ttk.Label(
    device_frame,
    text="Network Devices",
    font=("Segoe UI", 11, "bold")
).pack(pady=5)

device_columns = ("name", "ip", "mac")

device_tree = ttk.Treeview(device_frame, columns=device_columns, show="headings")

device_tree.tag_configure(
    "trusted",
    background="#1f5f3a"
)

device_tree.heading(
    "name",
    text="Device Name"
)

device_tree.heading(
    "ip",
    text="IP Address"
)

device_tree.heading(
    "mac",
    text="MAC Address"
)

device_tree.column("name", width=150)
device_tree.column("ip", width=140)
device_tree.column("mac", width=180)

device_tree.pack(
    fill="both",
    expand=True
)

menu = tk.Menu(root, tearoff=0)

menu.add_command(
    label="Rename Device",
    command=rename_device
)

menu.add_command(
    label="Mark Trusted",
    command=add_trusted
)

menu.add_command(
    label="Remove Trusted",
    command=remove_trusted
)

menu.add_separator()

menu.add_command(
    label="Filter Traffic",
    command=filter_selected_device
)

def show_context_menu(event):

    row = device_tree.identify_row(event.y)

    if row:

        device_tree.selection_set(row)

        menu.post(
            event.x_root,
            event.y_root
        )

device_tree.bind(
    "<Button-3>",
    show_context_menu
)


# STATISTICS PANEL
stats_frame = tk.Frame(root)
stats_frame.pack(pady=10)

tcp_label = ttk.Label(stats_frame, text="TCP: 0", font=("Segoe UI", 10))
tcp_label.pack(side="left", padx=20)

udp_label = ttk.Label(stats_frame, text="UDP: 0", font=("Segoe UI", 10))
udp_label.pack(side="left", padx=20)

icmp_label = ttk.Label(stats_frame, text="ICMP: 0", font=("Segoe UI", 10))
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
        ),
        tags=(protocol,)
    )

    tree.yview_moveto(1)

    tcp_label.config(text=f"TCP: {tcp_count}")
    udp_label.config(text=f"UDP: {udp_count}")
    icmp_label.config(text=f"ICMP: {icmp_count}")


status_label = ttk.Label(
    root,
    text="Ready",
    anchor="w"
)

status_label.pack(
    side=tk.BOTTOM,
    fill=tk.X,
    padx=5,
    pady=2
)
root.mainloop()