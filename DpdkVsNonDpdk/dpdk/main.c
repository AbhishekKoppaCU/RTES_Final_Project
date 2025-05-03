// Filename: dpdk_receiver.c

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define CAPTURE_DURATION_SEC 30

static volatile bool force_quit = false;
static struct rte_mempool *mbuf_pool;
static FILE *csv_file;
static time_t start_time;

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
        printf("\nSignal %d received, exiting...\n", signum);
    }
}
/*

static void log_packet(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    char src_mac[32], dst_mac[32];

    rte_ether_format_addr(src_mac, sizeof(src_mac), &eth_hdr->src_addr);
    rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth_hdr->dst_addr);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;

    fprintf(csv_file, "%lu,%s,%s\n", timestamp_us, src_mac, dst_mac);
    fflush(csv_file);
}*/
static void log_packet(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    char src_mac[32], dst_mac[32];
    char id_str[16] = "NA";  // Default if ID not found

    rte_ether_format_addr(src_mac, sizeof(src_mac), &eth_hdr->src_addr);
    rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth_hdr->dst_addr);

    // Calculate timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_us = ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;

    // Attempt to extract "ID:<number>" from payload
    char *payload_start = (char *)eth_hdr + sizeof(struct rte_ether_hdr);
    uint16_t payload_len = rte_pktmbuf_pkt_len(mbuf) - sizeof(struct rte_ether_hdr);
    if (payload_len > 0 && payload_len < 1500) {  // Sanity check
        char payload_buf[1501] = {0};
        rte_memcpy(payload_buf, payload_start, payload_len);
        payload_buf[payload_len] = '\0';

        // Look for "ID:"
        char *id_pos = strstr(payload_buf, "ID:");
        if (id_pos != NULL) {
            sscanf(id_pos, "ID:%15s", id_str);
        }
    }

    // Write to CSV with ID
    fprintf(csv_file, "%lu,%s,%s,%s\n", timestamp_us, src_mac, dst_mac, id_str);
    fflush(csv_file);
}

int main(int argc, char *argv[])
{
    uint16_t port_id = 0;
    struct rte_mbuf *mbufs[BURST_SIZE];

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    struct rte_eth_conf port_conf = {0};
    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure port %u\n", port_id);

    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
        rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to start port %u\n", port_id);

    printf("DPDK Sniffer started on port %u\n", port_id);

    csv_file = fopen("dpdk_packet_log.csv", "w");
    if (!csv_file)
        rte_exit(EXIT_FAILURE, "Failed to open CSV file\n");
fprintf(csv_file, "Timestamp_us,Source MAC,Destination MAC,ID\n");


    start_time = time(NULL);

    while (!force_quit) {
        const uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, BURST_SIZE);

        for (int i = 0; i < nb_rx; i++) {
            log_packet(mbufs[i]);
            rte_pktmbuf_free(mbufs[i]);
        }

        if (time(NULL) - start_time >= CAPTURE_DURATION_SEC) {
            force_quit = true;
        }
    }

    fclose(csv_file);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();

    printf("DPDK Receiver exiting...\n");
    return 0;
}
