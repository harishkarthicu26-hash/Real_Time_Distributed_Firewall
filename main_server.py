import os
import time
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional

from rules_and_sim import TrafficSimulator
from firewall_orchestrator import FirewallController, ReusableHTTPServer, cleanup_stale_ports, make_gateway_handler, start_udp_listener

def make_dashboard_handler(controller: FirewallController, simulator: Optional[TrafficSimulator] = None):
    sim = simulator or TrafficSimulator(controller)

    class WebUI(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/":
                try:
                    with open(controller.html_file, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.end_headers()
                    self.wfile.write(content.encode("utf-8"))
                except FileNotFoundError:
                    self.send_error(404, f"Missing {controller.html_file}. Ensure dashboard.html is in this folder.")

            elif parsed.path == "/api/telemetry":
                payload = {
                    "config": {
                        "host_ip": controller.host_ip,
                        "http_port": controller.http_port,
                        "udp_port": controller.udp_port
                    },
                    "total_processed": controller.total_processed,
                    "total_allowed": controller.total_allowed,
                    "total_dropped": controller.total_dropped,
                    "last_latency_us": controller.last_latency_us,
                    "head": controller.logger.head,
                    "tail": controller.logger.tail,
                    "ring_buffer": [
                        {"ip": s.droppedIp, "rule": s.ruleMatched} if s else None
                        for s in controller.logger.buffer
                    ],
                    "recent_logs": [
                        {
                            "time": time.strftime('%H:%M:%S', time.localtime(e.timestamp)),
                            "ip": e.droppedIp,
                            "rule": e.ruleMatched
                        }
                        for e in controller.logger.getRecentLogs()
                    ],
                    "rules": controller.active_rules,
                    "recent_packets": controller.recent_packets,
                    "last_trace": controller.last_trace
                }
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode("utf-8"))

            elif parsed.path == "/api/check":
                ip = parse_qs(parsed.query).get("ip", ["192.168.1.140"])[0]
                try:
                    controller.processPacket(ip, "UI-TEST")
                except Exception:
                    pass
                self.send_response(200)
                self.end_headers()

            elif parsed.path == "/api/ban":
                q = parse_qs(parsed.query)
                if "cidr" in q:
                    try:
                        controller.appendRule(q["cidr"][0], q.get("name", ["Manual_Block"])[0])
                    except Exception:
                        pass
                self.send_response(200)
                self.end_headers()

            elif parsed.path == "/api/remove":
                q = parse_qs(parsed.query)
                if "cidr" in q:
                    controller.removeRule(q["cidr"][0])
                self.send_response(200)
                self.end_headers()

            elif parsed.path == "/api/reset":
                controller.resetRules()
                self.send_response(200)
                self.end_headers()

            elif parsed.path == "/api/simulate":
                count = int(parse_qs(parsed.query).get("count", ["25"])[0])
                sim.startSimulation(count)
                self.send_response(200)
                self.end_headers()

        def log_message(self, format, *args):
            pass
    return WebUI

if __name__ == "__main__":
    cleanup_stale_ports([8080, 5000, 9999])
    controller = FirewallController(http_port=8080, web_ui_port=5000, udp_port=9999)
    controller.initialize()
    simulator = TrafficSimulator(controller)

    threading.Thread(
        target=ReusableHTTPServer(("0.0.0.0", controller.http_port), make_gateway_handler(controller)).serve_forever,
        daemon=True
    ).start()
    threading.Thread(
        target=ReusableHTTPServer(("0.0.0.0", controller.web_ui_port), make_dashboard_handler(controller, simulator)).serve_forever,
        daemon=True
    ).start()
    threading.Thread(
        target=start_udp_listener,
        args=(controller,),
        daemon=True
    ).start()

    local_ips = []
    try:
        _, _, local_ips = socket.gethostbyname_ex(socket.gethostname())
    except Exception:
        local_ips = [controller.host_ip]

    print("============================================================================")
    print("  BALANCED & MODULAR FIREWALL ONLINE (PYTHON)")
    print("============================================================================")
    print(f"  [DASHBOARD] Open on this laptop : http://localhost:{controller.web_ui_port}")
    print("----------------------------------------------------------------------------")
    print("  [NETWORK] Detected IPs (Use one of these in sender.py on other laptops):")
    for ip in local_ips:
        if not ip.startswith("127."):
            print(f"            -> {ip}")
    print("----------------------------------------------------------------------------")
    print(f"  HTTP Gateway Port : {controller.http_port}  |  UDP Socket Port : {controller.udp_port}")
    print("============================================================================")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        os._exit(0)
