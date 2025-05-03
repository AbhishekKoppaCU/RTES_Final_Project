from scapy.all import Ether, IP, TCP, UDP, sendp
import random
import threading
import time

# Raspberry Pi Ethernet MAC Address
RPI_MAC_ADDRESS = "d8:3a:dd:9c:d8:7e"

# Laptop Ethernet Interface Name
INTERFACE = "Ethernet 8"

# Destination IP (RPi eth0)
RPI_IP_ADDRESS = "192.168.1.2"

NUM_THREADS = 4  # Number of parallel sending threads

def generate_packet():
    ether = Ether(dst=RPI_MAC_ADDRESS)
    ip = IP(dst=RPI_IP_ADDRESS)
    if random.choice(["TCP", "UDP"]) == "TCP":
        payload = ether / ip / TCP(dport=random.randint(1024, 65535))
    else:
        payload = ether / ip / UDP(dport=random.randint(1024, 65535))
    return payload

def send_packets():
    while True:
        pkt = generate_packet()
        sendp(pkt, iface=INTERFACE, verbose=False)

def main():
    print(f"[STARTING] Launching {NUM_THREADS} sending threads...")

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=send_packets)
        t.daemon = True
        t.start()
        threads.append(t)

    # Keep main thread alive
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
