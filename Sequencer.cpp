#include "Sequencer.hpp"
#include <thread>
#include <chrono>
#include <csignal>
#include <syslog.h>


extern "C" {
    #include <rte_eal.h>
    #include <rte_ethdev.h>
    #include <rte_mbuf.h>
    #include <rte_ring.h>
    #include "packet_logger.h"
    #include "server_service.h"

}
#include <cstdlib> // For atexit



pthread_t rx_thread, detect_thread, log_thread, led_thread;

int main(int argc, char *argv[]) {
    openlog("PthreadService", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);

    syslog(LOG_INFO, "Starting DPDK packet sniffer with sequencer-controlled services...");
    
    // Initialize DPDK
    if (rte_eal_init(argc, argv) < 0) {
        syslog(LOG_ERR, "Failed to initialize DPDK EAL");
        return -1;
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create mbuf pool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        syslog(LOG_ERR, "Cannot create mbuf pool");
        return -1;
    }

    // Configure Ethernet port
    struct rte_eth_conf port_conf = {};
    if (rte_eth_dev_configure(port_id, 1, 0, &port_conf) < 0 ||
        rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) < 0 ||
        rte_eth_dev_start(port_id) < 0) {
        syslog(LOG_ERR, "Failed to configure/start port %u", port_id);
        return -1;
    }

    // Create CSV output
    csv_file = fopen("packet_logger.csv", "w");
    if (!csv_file) {
        syslog(LOG_ERR, "Failed to open CSV file");
        return -1;
    }
    fprintf(csv_file, "Timestamp,Source MAC,Destination MAC,Threat Status\n");

    // Create rings
    // New
    packet_ring = rte_ring_create(PACKET_RING_NAME, 2048, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    detected_ring = rte_ring_create(DETECTED_RING_NAME, 8192, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    //packet_ring = rte_ring_create(PACKET_RING_NAME, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    //detected_ring = rte_ring_create(DETECTED_RING_NAME, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!packet_ring || !detected_ring) {
        syslog(LOG_ERR, "Failed to create rings");
        return -1;
    }

    // Create Sequencer
    Sequencer sequencer;
    int max_priority = sched_get_priority_max(SCHED_FIFO);


    // Add services directly (real functional services)
    sequencer.addService(rx_service,     "RX",     RX_CORE_ID,        max_priority, INFINITE_PERIOD);   // RX service: every 5 ms
    sequencer.addService(detect_service, "DETECT", DETECTION_CORE_ID, max_priority, INFINITE_PERIOD);   // Detection service: every 5 ms
    sequencer.addService(server_service,    "SERVER",    LOGGER_CORE_ID,    max_priority-1, 10);   // LED service: every 5 ms
    sequencer.addService(logger_service, "LOGGER", LOGGER_CORE_ID,    max_priority, 2);  // Logger service: every 10 ms


    // Start the sequencer
    sequencer.startServices();



    // Run system
while (!force_quit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }


    // Stop the sequencer
    sequencer.stopServices();


    struct rte_eth_stats stats;
    if (rte_eth_stats_get(port_id, &stats) == 0) {
        syslog(LOG_INFO,"Packets RX: %" PRIu64 "\n", stats.ipackets);
        syslog(LOG_INFO,"Packets dropped RX: %" PRIu64 "\n", stats.imissed);
    } else {
        syslog(LOG_INFO,"Failed to get Ethernet stats!\n");
    }

    fclose(csv_file);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();

    syslog(LOG_INFO, "Shutdown complete. Total packets received: %lu", total_rx);
    closelog();

    syslog(LOG_INFO,"Running WCET plotting script...\n");
    system("python3 plot_wcet.py");

    return 0;
}


