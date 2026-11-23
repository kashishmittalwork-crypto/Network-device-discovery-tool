
import threading
import time
import scanner
import database

NETWORK_RANGE = "172.27.32.0/24"
SCAN_INTERVAL = 30

monitoring = False
devices = {}
monitor_lock = threading.Lock()


def add_alert(message, severity="INFO"):
    alert = {
        "message": message,
        "severity": severity,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    database.save_alert(alert)


def scan_once():
    global devices

    discovered = scanner.scan_network(NETWORK_RANGE)

    # Do not mark everything offline if discovery fails
    if discovered is None:
        return list(devices.values())

    current_ips = set()

    with monitor_lock:
        for item in discovered:
            ip = item.get("ip")

            if not ip:
                continue

            current_ips.add(ip)

            device = {
                "ip": ip,
                "mac": item.get("mac", "Unknown"),
                "hostname": item.get("hostname", "Unknown"),
                "status": "Online"
            }

            if ip not in devices:
                add_alert(f"New device detected: {ip}", "WARNING")

            devices[ip] = device
            database.save_device(device)

        # Mark offline only if valid devices were discovered
        if current_ips:
            for ip, device in devices.items():
                if ip not in current_ips and device["status"] != "Offline":
                    device["status"] = "Offline"
                    database.save_device(device)
                    add_alert(f"Device went offline: {ip}", "WARNING")

    return list(devices.values())


def monitor_network():
    global monitoring

    while monitoring:
        try:
            scan_once()
        except Exception as error:
            add_alert(f"Monitoring error: {error}", "ERROR")

        time.sleep(SCAN_INTERVAL)


def start_monitoring():
    global monitoring

    if not monitoring:
        monitoring = True
        thread = threading.Thread(target=monitor_network, daemon=True)
        thread.start()
        add_alert("Network monitoring started")


def stop_monitoring():
    global monitoring
    monitoring = False
    add_alert("Network monitoring stopped")
