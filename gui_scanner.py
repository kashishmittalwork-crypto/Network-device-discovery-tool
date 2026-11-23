import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp
import socket
import threading


def start_scan():
    network = network_entry.get().strip()

    if not network:
        messagebox.showerror("Error", "Enter a network range.")
        return

    scan_button.config(state="disabled")
    status_label.config(text="Scanning...")

    # Remove old results
    for item in table.get_children():
        table.delete(item)

    # Run scan in background
    threading.Thread(
        target=scan_network,
        args=(network,),
        daemon=True
    ).start()


def scan_network(network):

    try:
        # Create ARP request
        arp_request = ARP(pdst=network)

        # Create Ethernet broadcast
        broadcast = Ether(
            dst="ff:ff:ff:ff:ff:ff"
        )

        # Combine Ethernet + ARP
        packet = broadcast / arp_request

        # Send and receive
        answered = srp(
            packet,
            timeout=2,
            verbose=False
        )[0]

        devices = []

        for sent, received in answered:

            ip = received.psrc
            mac = received.hwsrc

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"

            devices.append(
                (ip, mac, hostname)
            )

        # Update GUI
        root.after(
            0,
            show_results,
            devices
        )

    except Exception as error:

        root.after(
            0,
            show_error,
            str(error)
        )


def show_results(devices):

    for ip, mac, hostname in devices:

        table.insert(
            "",
            "end",
            values=(ip, mac, hostname)
        )

    count_label.config(
        text=f"Devices Found: {len(devices)}"
    )

    status_label.config(
        text="Scan completed!"
    )

    scan_button.config(
        state="normal"
    )


def show_error(error):

    messagebox.showerror(
        "Scan Error",
        error
    )

    status_label.config(
        text="Scan failed"
    )

    scan_button.config(
        state="normal"
    )


# -----------------------------
# GUI WINDOW
# -----------------------------

root = tk.Tk()

root.title(
    "Network Device Discovery Tool"
)

root.geometry(
    "850x550"
)


# Title

title = tk.Label(
    root,
    text="NETWORK DEVICE DISCOVERY TOOL",
    font=("Arial", 20, "bold")
)

title.pack(pady=20)


# Input area

input_frame = tk.Frame(root)

input_frame.pack(pady=10)


tk.Label(
    input_frame,
    text="Network Range:"
).pack(side="left")


network_entry = tk.Entry(
    input_frame,
    width=25
)

network_entry.pack(
    side="left",
    padx=10
)


network_entry.insert(
    0,
    "192.168.1.0/24"
)


# Scan button

scan_button = tk.Button(
    input_frame,
    text="SCAN",
    width=12,
    command=start_scan
)

scan_button.pack(
    side="left"
)


# Results table

columns = (
    "IP Address",
    "MAC Address",
    "Hostname"
)


table = ttk.Treeview(
    root,
    columns=columns,
    show="headings"
)


table.heading(
    "IP Address",
    text="IP Address"
)

table.heading(
    "MAC Address",
    text="MAC Address"
)

table.heading(
    "Hostname",
    text="Hostname"
)


table.column(
    "IP Address",
    width=200
)

table.column(
    "MAC Address",
    width=250
)

table.column(
    "Hostname",
    width=250
)


table.pack(
    padx=20,
    pady=20,
    fill="both",
    expand=True
)


# Device count

count_label = tk.Label(
    root,
    text="Devices Found: 0",
    font=("Arial", 12, "bold")
)

count_label.pack()


# Status

status_label = tk.Label(
    root,
    text="Ready to scan",
    font=("Arial", 10)
)

status_label.pack(
    pady=10
)


# Start GUI

root.mainloop()