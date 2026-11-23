
from scanner import scan_network

def discover_devices():
    network = "172.27.32.0/24"

    devices = scan_network(network)

    return devices


