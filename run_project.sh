#!/bin/bash
sudo pkill packet_logger
sudo rm -rf /var/run/dpdk
sudo ./packet_logger --vdev=net_af_packet0,iface=eth0 --no-huge -- -p 0x1
