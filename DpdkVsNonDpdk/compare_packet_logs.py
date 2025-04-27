import csv
import os

def analyze_csv(filename):
    timestamps = []

    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        return 0, 0, 0, 0

    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            timestamps.append(int(row['Timestamp_us']))

    packet_count = len(timestamps)
    duration_sec = (timestamps[-1] - timestamps[0]) / 1_000_000 if packet_count > 1 else 0
    packet_rate = packet_count / duration_sec if duration_sec > 0 else 0

    avg_delta_us = 0
    if packet_count > 1:
        deltas = [timestamps[i] - timestamps[i-1] for i in range(1, packet_count)]
        avg_delta_us = sum(deltas) / len(deltas)

    return packet_count, duration_sec, packet_rate, avg_delta_us

def main():
    dpdk_csv = 'dpdk/dpdk_packet_log.csv'
    non_dpdk_csv = 'Non_dpdk/non_dpdk_packet_log.csv'

    print("\n=== ?? Analyzing DPDK CSV ===")
    dpdk_packets, dpdk_duration, dpdk_rate, dpdk_avg_delta = analyze_csv(dpdk_csv)
    print(f"Total Packets        : {dpdk_packets}")
    print(f"Capture Duration     : {dpdk_duration:.2f} seconds")
    print(f"Packet Rate          : {dpdk_rate:.2f} packets/sec")
    print(f"Avg Time Between Packets: {dpdk_avg_delta:.2f} microseconds\n")

    print("=== ?? Analyzing Non-DPDK CSV ===")
    non_dpdk_packets, non_dpdk_duration, non_dpdk_rate, non_dpdk_avg_delta = analyze_csv(non_dpdk_csv)
    print(f"Total Packets        : {non_dpdk_packets}")
    print(f"Capture Duration     : {non_dpdk_duration:.2f} seconds")
    print(f"Packet Rate          : {non_dpdk_rate:.2f} packets/sec")
    print(f"Avg Time Between Packets: {non_dpdk_avg_delta:.2f} microseconds\n")

    print("=== ?? Comparison Summary ===")
    if dpdk_packets and non_dpdk_packets:
        print(f"DPDK captured {dpdk_packets - non_dpdk_packets} more packets than Non-DPDK.")
        if non_dpdk_rate > 0:
            print(f"DPDK packet rate is {dpdk_rate / non_dpdk_rate:.2f} times faster than Non-DPDK.")
    else:
        print("Error: Could not analyze packets correctly.")

if __name__ == "__main__":
    main()
