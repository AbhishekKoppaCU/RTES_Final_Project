from scapy.all import Ether, IP, ICMP, TCP, UDP, sendp
import random
import time

# Raspberry Pi Ethernet MAC Address
RPI_MAC_ADDRESS = "d8:3a:dd:9c:d8:7e"

# Laptop Ethernet Interface Name
INTERFACE = "Ethernet 2"

# Destination IP (RPi eth0)
RPI_IP_ADDRESS = "192.168.1.2"

def generate_packet():
    # Randomly decide whether to send THREAT or SAFE
    packet_type = random.choice(["SAFE", "THREAT"])

    ether = Ether(dst=RPI_MAC_ADDRESS)
    ip = IP(dst=RPI_IP_ADDRESS)

    if packet_type == "THREAT":
        payload = ether / ip / ICMP()
    else:
        if random.choice(["TCP", "UDP"]) == "TCP":
            payload = ether / ip / TCP(dport=random.randint(1024, 65535))
        else:
            payload = ether / ip / UDP(dport=random.randint(1024, 65535))

    return payload, packet_type

def main():
    while True:
        mode = random.choice(["NORMAL", "BURST"])

        if mode == "NORMAL":
            pkt, pkt_type = generate_packet()
            sendp(pkt, iface=INTERFACE, verbose=False)
            print(f"[NORMAL] Sent {pkt_type} packet")
            time.sleep(random.uniform(0.5, 1.5))  # Random delay between packets
        else:
            print("[BURST] Sending attack burst!")
            for _ in range(random.randint(50, 100)):  # Send 50–100 packets
                pkt, pkt_type = generate_packet()
                sendp(pkt, iface=INTERFACE, verbose=False)
            time.sleep(random.uniform(3, 5))  # Wait after burst

if __name__ == "__main__":
    main()
