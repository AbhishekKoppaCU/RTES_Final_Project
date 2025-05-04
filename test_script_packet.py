from scapy.all import Ether, IP, UDP, TCP, ICMP, Raw, sendp
import random
import threading
import time
import socket

# Koppa realted settings
# # Raspberry Pi Ethernet MAC Address
# RPI_MAC_ADDRESS = "d8:3a:dd:9c:d7:26"

# # Laptop Ethernet Interface Name (adjust as needed)
# INTERFACE = "Ethernet 5"

# # Destination IP (RPi eth0)
# RPI_IP_ADDRESS = "192.168.1.100"

RPI_MAC_ADDRESS = "d8:3a:dd:9c:d8:7e"

# Laptop Ethernet Interface Name
INTERFACE = "Ethernet 2"

# Destination IP (RPi eth0)
RPI_IP_ADDRESS = "192.168.1.2"


RPI_UDP_PORT = 9999
SRC_PORT = 12345  # fixed source port so RPi can reply

NAMES = ["Parth", "Jainil", "Varsani", "Nadgir", "Koppa",
         "Nalin", "Karthik", "Abhirath", "Aditya", "Induja"]

NUM_THREADS = 4

# Global shared variable for matching response
last_sent_name = None
lock = threading.Lock()

def generate_random_packet():
    """Randomly generate a SAFE (TCP/UDP) or THREAT (ICMP) packet."""
    ether = Ether(dst=RPI_MAC_ADDRESS)
    ip = IP(dst=RPI_IP_ADDRESS)

    # 50% chance to send ICMP (THREAT), else send TCP/UDP (SAFE)
    if random.choice([True, False]):
        return ether / ip / ICMP()
    else:
        if random.choice(["TCP", "UDP"]) == "TCP":
            return ether / ip / TCP(dport=random.randint(1024, 65535))
        else:
            return ether / ip / UDP(dport=random.randint(1024, 65535))

def send_noise():
    while True:
        pkt = generate_random_packet()
        sendp(pkt, iface=INTERFACE, verbose=False)

def send_get_packet():
    global last_sent_name
    while True:
        name = random.choice(NAMES)
        payload_str = f"type=GET;resource={name}"

        ether = Ether(dst=RPI_MAC_ADDRESS)
        ip = IP(dst=RPI_IP_ADDRESS)
        udp = UDP(sport=SRC_PORT, dport=RPI_UDP_PORT)
        payload = ether / ip / udp / Raw(load=payload_str)

        with lock:
            last_sent_name = name  # store for response display

        sendp(payload, iface=INTERFACE, verbose=False)
        time.sleep(2)  # 2 second interval

def listen_for_response_socket():
    global last_sent_name
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("192.168.1.4", SRC_PORT))

    print("[LISTENER] Waiting for UDP replies on port 12345...")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            response = data.decode(errors='ignore')
            with lock:
                print(f"[RESULT] GET '{last_sent_name}' -> {response}")
        except Exception as e:
            print(f"[ERROR] Socket receive failed: {e}")

def main():
    print(f"[STARTING] Launching {NUM_THREADS} mixed noise threads, GET sender (2s interval), and listener...")

    for _ in range(NUM_THREADS):
        threading.Thread(target=send_noise, daemon=True).start()

    threading.Thread(target=send_get_packet, daemon=True).start()
    threading.Thread(target=listen_for_response_socket, daemon=True).start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
