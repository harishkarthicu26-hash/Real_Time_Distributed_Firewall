import os
import time
import socket
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from typing import List, Optional, Tuple

from core_data_structures import BinaryRadixTree, CircularQueue, LogEvent, Packet
from rules_and_sim import RuleLoader, CIDRParser, DashboardUI

class FirewallController:
    def __init__(self, http_port: int = 8080, web_ui_port: int = 5000, udp_port: int = 9999):
        self.radixTree = BinaryRadixTree()
        self.logger = CircularQueue(capacity=8)
        self.ruleLoader = RuleLoader()
        self.parser = CIDRParser()
        self.dashboard = DashboardUI(self.logger)
        self.http_port, self.web_ui_port, self.udp_port = http_port, web_ui_port, udp_port

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            self.host_ip = s.getsockname()[0]
        except Exception:
            self.host_ip = "127.0.0.1"
        finally:
            s.close()

        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.rules_file = os.path.join(self.script_dir, "blacklist_rules.txt")
        self.html_file = os.path.join(self.script_dir, "dashboard.html")

        self.active_rules, self.recent_packets, self.last_trace = [], [], {}
        self.total_processed = self.total_allowed = self.total_dropped = 0
        self.last_latency_us = 0.0
        self._lock = threading.Lock()

    def initialize(self) -> None:
        self.radixTree = BinaryRadixTree()
        loaded = self.ruleLoader.loadRules(self.rules_file)
        self.active_rules = []
        for cidr, binary_prefix, rule_name in loaded:
            self.radixTree.insertRule(binary_prefix, rule_name)
            self.active_rules.append({"cidr": cidr, "prefix": binary_prefix, "name": rule_name})

    def appendRule(self, cidr: str, rule_name: str) -> None:
        cidr = cidr.strip()
        if '/' not in cidr:
            cidr = f"{cidr}/32"
        self.parser.parseCIDR(cidr)
        with open(self.rules_file, "a", encoding="utf-8") as f:
            f.write(f"\n{cidr}, {rule_name.strip()}")
        self.initialize()

    def removeRule(self, target_cidr: str) -> None:
        if not os.path.exists(self.rules_file):
            return
        target = target_cidr.strip()
        with open(self.rules_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(self.rules_file, "w", encoding="utf-8") as f:
            for line in lines:
                if line.strip() and line.split(",", 1)[0].strip() != target:
                    f.write(line)
        self.initialize()

    def resetRules(self) -> None:
        if os.path.exists(self.rules_file):
            os.remove(self.rules_file)
        self.initialize()

    def processPacket(self, ip: str, protocol: str = "HTTP") -> Tuple[bool, Optional[str]]:
        t0 = time.perf_counter()
        binaryIp = self.parser.ipToBinary(ip)
        pkt = Packet(ip, self.host_ip, binaryIp)
        matched_node, steps = self.radixTree.tracePacketWithPath(pkt.getBinaryIp())

        with self._lock:
            self.last_latency_us = round((time.perf_counter() - t0) * 1_000_000, 2)
            self.total_processed += 1
            is_allowed = matched_node is None or not matched_node.isBanned()
            rule_name = None if is_allowed else matched_node.ruleName

            if not is_allowed:
                self.total_dropped += 1
                self.logger.enqueue(LogEvent(pkt.timestamp, pkt.sourceIp, rule_name))
            else:
                self.total_allowed += 1

            self.last_trace = {
                "ip": pkt.sourceIp,
                "binaryIp": pkt.getBinaryIp(),
                "allowed": is_allowed,
                "rule": rule_name,
                "steps": steps
            }
            self.recent_packets.insert(0, {
                "time": time.strftime('%H:%M:%S', time.localtime(pkt.timestamp)),
                "ip": pkt.sourceIp,
                "proto": protocol,
                "allowed": is_allowed
            })
            self.recent_packets = self.recent_packets[:50]
            return is_allowed, rule_name

class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

def cleanup_stale_ports(ports: List[int]) -> None:
    if os.name != "nt":
        return
    my_pid = os.getpid()
    try:
        output = subprocess.check_output("netstat -ano", shell=True, text=True)
        for line in output.splitlines():
            for port in ports:
                if f":{port} " in line:
                    parts = line.strip().split()
                    if parts and parts[-1].isdigit() and int(parts[-1]) not in (0, my_pid):
                        subprocess.run(f"taskkill /F /PID {parts[-1]}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def make_gateway_handler(controller: FirewallController):
    class Gateway(BaseHTTPRequestHandler):
        def do_GET(self):
            ip = parse_qs(urlparse(self.path).query).get("ip", [self.client_address[0]])[0]
            try:
                allowed, rule = controller.processPacket(ip, "HTTP")
            except Exception:
                return self.send_error(400, "Invalid IPv4 format")
            self.send_response(200 if allowed else 403)
            self.end_headers()
            msg = f"ALLOWED ({ip})" if allowed else f"DROPPED ({ip}) -> {rule}"
            self.wfile.write(msg.encode("utf-8"))
        def log_message(self, format, *args):
            pass
    return Gateway

def start_udp_listener(controller: FirewallController):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", controller.udp_port))
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode('utf-8', errors='ignore').strip()
            ip = msg.split("SPOOF:")[1].strip() if "SPOOF:" in msg else addr[0]
            allowed, rule = controller.processPacket(ip, "UDP")
            sock.sendto((f"ALLOWED ({ip})" if allowed else f"DROPPED ({ip}) -> {rule}").encode("utf-8"), addr)
        except Exception:
            pass
