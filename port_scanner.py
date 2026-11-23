
import subprocess
import re
import database

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP"
}

MEDIUM_RISK_PORTS = {
    22: "SSH",
    80: "HTTP",
    8080: "HTTP Alternate",
    3306: "MySQL",
    5432: "PostgreSQL"
}


def calculate_risk(port):
    port = int(port)

    if port in HIGH_RISK_PORTS:
        return "HIGH"

    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"

    return "LOW"


def scan_ports(ip):
    print(f"Scanning ports on {ip}...")

    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", ip],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return [{"error": result.stderr.strip() or "Nmap failed"}]

        ports = []

        for line in result.stdout.splitlines():

            match = re.match(
                r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?",
                line
            )

            if match:
                port = int(match.group(1))
                service = match.group(2)
                version = (match.group(3) or "Unknown").strip()
                risk = calculate_risk(port)

                item = {
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": risk
                }

                ports.append(item)

                database.save_port_scan(
                    ip, port, service, version, risk
                )

                if risk == "HIGH":
                    database.save_alert({
                        "time": __import__("time").strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "severity": "WARNING",
                        "message": f"Potentially risky port {port} open on {ip}"
                    })

        return ports

    except subprocess.TimeoutExpired:
        return [{"error": "Scan timed out"}]

    except Exception as error:
        return [{"error": str(error)}]


if __name__ == "__main__":
    target = input("Enter target IP: ")

    results = scan_ports(target)

    print("\nOpen Ports:")
    print("-" * 60)

    for port in results:
        print(port)

    print("-" * 60)
