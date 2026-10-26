import os
import random
from typing import List, Tuple, Optional

class CIDRParser:
    def ipToBinary(self, ip: str) -> str:
        octets = ip.strip().split('.')
        if len(octets) != 4:
            raise ValueError(f"Invalid IPv4: {ip}")
        for o in octets:
            val = int(o)
            if val < 0 or val > 255:
                raise ValueError(f"Octet out of range: {o}")
        return ''.join(f"{int(octet):08b}" for octet in octets)

    def parseCIDR(self, cidr: str) -> str:
        if '/' in cidr:
            ip_part, mask_len = cidr.strip().split('/')
            mask = int(mask_len)
            if mask < 0 or mask > 32:
                raise ValueError(f"Invalid CIDR mask: {mask}")
            return self.ipToBinary(ip_part)[:mask]
        return self.ipToBinary(cidr)

class RuleLoader:
    def __init__(self):
        self.parser = CIDRParser()
        self.default_rules = """192.168.0.0/16, Internal_Quarantine_Zone
192.168.1.0/24, Mirai_IoT_Botnet_Cluster
192.168.1.128/25, Mirai_C2_High_Severity_Subblock
10.10.45.0/24, DNS_Amplification_DDoS_Pool
172.16.0.0/12, Tor_Exit_Relay_Infrastructure
203.0.113.128/25, XMRig_Cryptomining_Botnet
198.51.100.42/32, ZeroDay_RCE_Exploit_Host
185.220.101.0/24, DarkWeb_Proxy_Scanner_Net
45.155.205.0/24, Log4Shell_Automated_Scanner
91.219.236.0/24, LockBit_Ransomware_C2_Subnet
194.26.192.0/22, BruteForce_SSH_Credential_Stuffer
5.188.206.0/24, Spamhaus_DROP_Malicious_ASN
103.27.108.0/23, Phishing_Redirector_Cluster
89.248.165.0/24, Masscan_Port_Sweep_Botnet
193.163.125.0/24, Feodo_Banking_Trojan_C2
179.43.176.0/21, Bulletproof_Hosting_Malware_Net"""

    def loadRules(self, filePath: str) -> List[Tuple[str, str, str]]:
        if not os.path.exists(filePath):
            with open(filePath, "w", encoding="utf-8") as f:
                f.write(self.default_rules + "\n")
        else:
            with open(filePath, "r", encoding="utf-8") as f:
                existing = f.read()
            if "Shadow Botnet Subnet A" in existing or not existing.strip():
                with open(filePath, "w", encoding="utf-8") as f:
                    f.write(self.default_rules + "\n")

        parsed_rules = []
        with open(filePath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(",", 1)
                    cidr = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else f"Block-{cidr}"
                    try:
                        parsed_rules.append((cidr, self.parser.parseCIDR(cidr), name))
                    except ValueError:
                        continue
        return parsed_rules

class TrafficSimulator:
    def __init__(self, controller: Any):
        self.controller = controller

    def startSimulation(self, count: int = 25) -> None:
        for _ in range(count):
            choice = random.choice([
                "quarantine_16", "mirai_24", "mirai_c2_25", "ddos_24",
                "tor_12", "xmrig_25", "zeroday_32", "lockbit_24",
                "ssh_22", "clean_dns", "clean_web"
            ])
            if choice == "quarantine_16":
                ip = f"192.168.{random.randint(2, 250)}.{random.randint(1, 254)}"
            elif choice == "mirai_24":
                ip = f"192.168.1.{random.randint(1, 126)}"
            elif choice == "mirai_c2_25":
                ip = f"192.168.1.{random.randint(129, 254)}"
            elif choice == "ddos_24":
                ip = f"10.10.45.{random.randint(1, 254)}"
            elif choice == "tor_12":
                ip = f"172.{random.randint(16, 31)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            elif choice == "xmrig_25":
                ip = f"203.0.113.{random.randint(129, 254)}"
            elif choice == "zeroday_32":
                ip = "198.51.100.42"
            elif choice == "lockbit_24":
                ip = f"91.219.236.{random.randint(1, 254)}"
            elif choice == "ssh_22":
                ip = f"194.26.{random.randint(192, 195)}.{random.randint(1, 254)}"
            elif choice == "clean_dns":
                ip = f"{random.choice(['8.8.8', '1.1.1', '9.9.9'])}.{random.randint(1, 254)}"
            else:
                ip = f"{random.choice(['142.250.190', '151.101.1', '104.16.132'])}.{random.randint(1, 254)}"
            
            self.controller.processPacket(ip, protocol="SIM")

class DashboardUI:
    def __init__(self, logger: Any):
        self.logger = logger
