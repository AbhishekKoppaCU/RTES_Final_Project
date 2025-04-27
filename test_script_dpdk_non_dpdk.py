from scapy.all import Ether, IP, TCP, UDP, sendp
import random

# Raspberry Pi Ethernet MAC Address
RPI_MAC_ADDRESS = "d8:3a:dd:9c:d8:7e"

# Laptop Ethernet Interface Name
INTERFACE = "Ethernet 2"

# Destination IP (RPi eth0)
RPI_IP_ADDRESS = "192.168.1.2"

def generate_packet():
    ether = Ether(dst=RPI_MAC_ADDRESS)
    ip = IP(dst=RPI_IP_ADDRESS)
    
    # Randomly choose between TCP and UDP packets
    if random.choice(["TCP", "UDP"]) == "TCP":
        payload = ether / ip / TCP(dport=random.randint(1024, 65535))
    else:
        payload = ether / ip / UDP(dport=random.randint(1024, 65535))

    return payload

def main():
    print("[STARTING] Sending full-speed packets to Raspberry Pi...")
    while True:
        pkt = generate_packet()
        sendp(pkt, iface=INTERFACE, verbose=False)  # No delay, no sleep

if __name__ == "__main__":
    main()
