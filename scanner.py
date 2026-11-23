
import subprocess
import socket
import ipaddress
import re
import psutil


def get_local_network():
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET:
                ip = address.address
                mask = address.netmask

                if ip.startswith("127.") or not mask:
                    continue

                network = ipaddress.ip_network(
                    f"{ip}/{mask}", strict=False
                )

                # Limit scanning to 256 addresses
                if network.num_addresses > 256:
                    network = ipaddress.ip_network(
                        f"{ip}/24", strict=False
                    )

                return str(network)

    return None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def scan_network(network=None):
    if network is None:
        network = get_local_network()

    if not network:
        print("Network not detected!")
        return []

    print("Detected network:", network)
    print("Scanning with Nmap...")
    print("Please wait...\n")

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", network],
            capture_output=True,
            text=True,
            timeout=180
        )

        devices = []

        for line in result.stdout.splitlines():
            match = re.search(
                r"Nmap scan report for (.+)", line
            )

            if match:
                value = match.group(1).strip()

                ip_match = re.search(
                    r"\(([\d.]+)\)", value
                )

                ip = (
                    ip_match.group(1)
                    if ip_match
                    else value
                )

                devices.append({
                    "ip": ip,
                    "mac": "Unknown",
                    "hostname": get_hostname(ip),
                    "status": "Online"
                })

        return devices

    except subprocess.TimeoutExpired:
        print("Scan timed out!")
        return []

    except Exception as error:
        print("Scanning error:", error)
        return []


if __name__ == "__main__":
    devices = scan_network()

    print("\nDISCOVERED DEVICES")
    print("=" * 60)

    for device in devices:
        print(
            f"{device['ip']:<20}"
            f"{device['mac']:<25}"
            f"{device['hostname']}"
        )

    print("=" * 60)
    print("Devices found:", len(devices))
    print("Scan completed!")
