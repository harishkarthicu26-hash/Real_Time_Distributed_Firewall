import socket
import urllib.request
import urllib.error
import time
import random

# Use "127.0.0.1" on the same laptop, or one of the [NETWORK] IPs printed by firewall_system.py
FIREWALL_IP = "127.0.0.1"
HTTP_PORT = 8080
UDP_PORT = 9999

used_ips = set()

def generate_unique_ip() -> str:
    while True:
        category = random.choice([
            "quarantine_16", "mirai_24", "mirai_c2_25",
            "tor_12", "lockbit_24", "zeroday_32", "clean_public"
        ])
        if category == "quarantine_16":
            # Matches /16: 192.168.0.0/16 (Internal_Quarantine_Zone)
            ip = f"192.168.{random.randint(2, 250)}.{random.randint(1, 254)}"
        elif category == "mirai_24":
            # Matches /24 LPM: 192.168.1.0/24 (Mirai_IoT_Botnet_Cluster)
            ip = f"192.168.1.{random.randint(1, 126)}"
        elif category == "mirai_c2_25":
            # Matches /25 LPM: 192.168.1.128/25 (Mirai_C2_High_Severity_Subblock)
            ip = f"192.168.1.{random.randint(129, 254)}"
        elif category == "tor_12":
            # Matches /12: 172.16.0.0/12 (Tor_Exit_Relay_Infrastructure)
            ip = f"172.{random.randint(16, 31)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        elif category == "lockbit_24":
            # Matches /24: 91.219.236.0/24 (LockBit_Ransomware_C2_Subnet)
            ip = f"91.219.236.{random.randint(1, 254)}"
        elif category == "zeroday_32":
            # Matches /32: 198.51.100.42/32 (ZeroDay_RCE_Exploit_Host)
            ip = "198.51.100.42"
        else:
            # Clean traffic (Allowed)
            ip = f"{random.choice(['8.8.8', '1.1.1', '142.250.190'])}.{random.randint(1, 254)}"

        if ip not in used_ips or category == "zeroday_32":
            used_ips.add(ip)
            return ip

print(f"[*] Simulating advanced threat traffic to {FIREWALL_IP}...\n")
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.settimeout(2.0)

for i in range(1, 26):
    fake_ip = generate_unique_ip()
    protocol = random.choice(["UDP", "HTTP"])

    if protocol == "HTTP":
        try:
            with urllib.request.urlopen(f"http://{FIREWALL_IP}:{HTTP_PORT}/?ip={fake_ip}", timeout=2.0) as res:
                body = res.read().decode("utf-8", errors="ignore")
                print(f"[{i:02d}] {fake_ip:<15} [HTTP] -> {body}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            print(f"[{i:02d}] {fake_ip:<15} [HTTP] -> {body}")
        except Exception as ex:
            print(f"[{i:02d}] {fake_ip:<15} [HTTP] -> Error: {ex}")
    else:
        try:
            udp_sock.sendto(f"SPOOF:{fake_ip}".encode("utf-8"), (FIREWALL_IP, UDP_PORT))
            reply, _ = udp_sock.recvfrom(1024)
            print(f"[{i:02d}] {fake_ip:<15} [UDP]  -> {reply.decode('utf-8')}")
        except Exception as ex:
            print(f"[{i:02d}] {fake_ip:<15} [UDP]  -> Timeout: {ex}")

    time.sleep(0.3)