#!/bin/bash

echo "Starting DPDK and Non-DPDK captures simultaneously..."

# Run DPDK packet_logger with special command line arguments
(cd dpdk && sudo ./packet_logger --vdev=net_af_packet0,iface=eth0 --no-huge -- -p 0x1 > dpdk_log.txt 2>&1) &

# Run Non-DPDK receiver
(cd Non_dpdk && sudo ./non_dpdk_receiver > non_dpdk_log.txt 2>&1) &

# Wait for both processes
wait

echo "Both captures completed. Running analysis..."

# Run Python comparison
python3 compare_packet_logs.py
