
from flask import Flask, render_template_string, redirect, send_file
import monitor
import database
import port_scanner
import csv
import io

app = Flask(__name__)
database.init_db()

STYLE = """
<style>
body{background:#111827;color:white;font-family:Arial;padding:30px}
h1{color:#38bdf8}
table{width:100%;border-collapse:collapse;margin-bottom:25px}
th,td{border:1px solid #374151;padding:12px;text-align:left}
th{background:#1f2937}
a{color:#38bdf8}
.card{background:#1f2937;padding:20px;border-radius:10px}
</style>
"""

@app.route("/")
def home():
    devices = database.get_devices()
    alerts = database.get_alerts()
    scans = database.get_port_scans()

    total_devices = len(devices)
    online = sum(1 for d in devices if d["status"] == "Online")
    offline = total_devices - online
    total_scans = len(scans)
    high_risk = sum(1 for s in scans if s["risk"] == "HIGH")

    return render_template_string("""
    <html><head><title>NetSentinel</title>""" + STYLE + """
    </head><body>

    <h1>NetSentinel Network Monitoring</h1>

    <p>
    <a href="/start">Start Monitoring</a> |
    <a href="/stop">Stop Monitoring</a> |
    <a href="/scan">Scan Network</a> |
    <a href="/history">Scan History</a> |
    <a href="/export">Export CSV</a>
    </p>

    <h2>Dashboard Statistics</h2>

    <table>
    <tr><th>Total Devices</th><th>Online</th>
    <th>Offline</th><th>Port Scans</th><th>High Risk</th></tr>
    <tr>
    <td>{{ total }}</td><td>{{ online }}</td>
    <td>{{ offline }}</td><td>{{ scans }}</td>
    <td>{{ high }}</td>
    </tr>
    </table>

    <p>Monitoring Status: {{ monitoring }}</p>

    <h2>Discovered Devices</h2>

    <table>
    <tr><th>IP</th><th>MAC</th><th>Hostname</th>
    <th>Status</th><th>Actions</th></tr>

    {% for d in devices %}
    <tr>
    <td><a href="/device/{{ d.ip }}">{{ d.ip }}</a></td>
    <td>{{ d.mac }}</td><td>{{ d.hostname }}</td>
    <td>{{ d.status }}</td>
    <td><a href="/ports/{{ d.ip }}">Scan Ports</a></td>
    </tr>
    {% endfor %}
    </table>

    <h2>Security Alerts</h2>

    <table>
    <tr><th>Time</th><th>Severity</th><th>Message</th></tr>
    {% for a in alerts %}
    <tr><td>{{ a.time }}</td><td>{{ a.severity }}</td>
    <td>{{ a.message }}</td></tr>
    {% endfor %}
    </table>

    </body></html>
    """, devices=devices, alerts=alerts,
    monitoring=monitor.monitoring,
    total=total_devices, online=online,
    offline=offline, scans=total_scans, high=high_risk)


@app.route("/start")
def start():
    monitor.start_monitoring()
    return redirect("/")


@app.route("/stop")
def stop():
    monitor.stop_monitoring()
    return redirect("/")


@app.route("/scan")
def scan():
    try:
        monitor.scan_once()
    except Exception as error:
        monitor.add_alert(str(error), "ERROR")
    return redirect("/")


@app.route("/device/<ip>")
def device_details(ip):
    devices = database.get_devices()
    device = next((d for d in devices if d["ip"] == ip), None)

    if not device:
        return "Device not found", 404

    scans = [s for s in database.get_port_scans() if s["ip"] == ip]

    return render_template_string("""
    <html><head><title>Device Details</title>""" + STYLE + """
    </head><body>
    <h1>Device Details</h1>

    <table>
    <tr><th>IP</th><td>{{ d.ip }}</td></tr>
    <tr><th>MAC</th><td>{{ d.mac }}</td></tr>
    <tr><th>Hostname</th><td>{{ d.hostname }}</td></tr>
    <tr><th>Status</th><td>{{ d.status }}</td></tr>
    <tr><th>First Seen</th><td>{{ d.first_seen }}</td></tr>
    <tr><th>Last Seen</th><td>{{ d.last_seen }}</td></tr>
    </table>

    <h2>Port Scan History</h2>
    <table>
    <tr><th>Port</th><th>Service</th><th>Version</th>
    <th>Risk</th><th>Time</th></tr>
    {% for s in scans %}
    <tr><td>{{ s.port }}</td><td>{{ s.service }}</td>
    <td>{{ s.version }}</td><td>{{ s.risk }}</td>
    <td>{{ s.scan_time }}</td></tr>
    {% endfor %}
    </table>

    <a href="/ports/{{ d.ip }}">Scan Device</a> |
    <a href="/">Dashboard</a>
    </body></html>
    """, d=device, scans=scans)


@app.route("/ports/<ip>")
def scan_device_ports(ip):
    results = port_scanner.scan_ports(ip)

    return render_template_string("""
    <html><head><title>Port Results</title>""" + STYLE + """
    </head><body>
    <h1>Port Scan Results: {{ ip }}</h1>
    <table>
    <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr>
    {% for p in results %}
    <tr><td>{{ p.get("port","-") }}</td>
    <td>{{ p.get("service",p.get("error","-")) }}</td>
    <td>{{ p.get("version","-") }}</td>
    <td>{{ p.get("risk","-") }}</td></tr>
    {% endfor %}
    </table>
    <a href="/device/{{ ip }}">Device Details</a> |
    <a href="/">Dashboard</a>
    </body></html>
    """, ip=ip, results=results)


@app.route("/history")
def history():
    scans = database.get_port_scans()

    return render_template_string("""
    <html><head><title>History</title>""" + STYLE + """
    </head><body>
    <h1>Port Scan History</h1>
    <a href="/export">Download CSV</a>
    <table>
    <tr><th>IP</th><th>Port</th><th>Service</th>
    <th>Version</th><th>Risk</th><th>Time</th></tr>
    {% for s in scans %}
    <tr><td>{{ s.ip }}</td><td>{{ s.port }}</td>
    <td>{{ s.service }}</td><td>{{ s.version }}</td>
    <td>{{ s.risk }}</td><td>{{ s.scan_time }}</td></tr>
    {% endfor %}
    </table>
    <a href="/">Dashboard</a>
    </body></html>
    """, scans=scans)


@app.route("/export")
def export_report():
    scans = database.get_port_scans()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["IP", "Port", "Service", "Version", "Risk", "Time"])

    for s in scans:
        writer.writerow([
            s["ip"], s["port"], s["service"],
            s["version"], s["risk"], s["scan_time"]
        ])

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="NetSentinel_Report.csv"
    )


if __name__ == "__main__":
    app.run(debug=False)
