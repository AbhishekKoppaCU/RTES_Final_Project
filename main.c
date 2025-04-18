/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <syslog.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RX_DESC_DEFAULT 1024
#define LOG_IDENTIFIER "dpdk_sniffer"

static volatile bool force_quit;
static struct rte_mempool *mbuf_pool;

/* Per-port statistics struct */
struct port_statistics {
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;

static struct port_statistics stats[RTE_MAX_ETHPORTS];

static void
packet_sniff_loop(void) {
	uint16_t portid;
	uint16_t nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint8_t *pkt_data;
	unsigned i;

	openlog(LOG_IDENTIFIER, LOG_PID | LOG_NDELAY, LOG_USER);

	while (!force_quit) {
		RTE_ETH_FOREACH_DEV(portid) {
			nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

			stats[portid].rx += nb_rx;

			for (i = 0; i < nb_rx; i++) {
				struct rte_mbuf *m = pkts_burst[i];
				pkt_data = rte_pktmbuf_mtod(m, uint8_t *);
				syslog(LOG_INFO, "Port %u: Received packet of length %u", portid, rte_pktmbuf_pkt_len(m));
				syslog(LOG_DEBUG, "First 16 bytes:");
				for (int j = 0; j < 16 && j < rte_pktmbuf_pkt_len(m); j++) {
					syslog(LOG_DEBUG, "%02x ", pkt_data[j]);
				}
				rte_pktmbuf_free(m);
			}
		}
	}

	closelog();
}

static void
signal_handler(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
	}
}

int
main(int argc, char **argv) {
	int ret;
	uint16_t portid;
	uint16_t nb_ports;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No available Ethernet ports\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_conf port_conf = { 0 };
		ret = rte_eth_dev_configure(portid, 1, 0, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: port %u\n", portid);

		ret = rte_eth_rx_queue_setup(portid, 0, RX_DESC_DEFAULT, rte_eth_dev_socket_id(portid), NULL, mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot setup RX queue: port %u\n", portid);

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot start device: port %u\n", portid);
	}

	packet_sniff_loop();

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}

	rte_eal_cleanup();
	printf("Sniffer terminated.\n");
	return 0;
}
