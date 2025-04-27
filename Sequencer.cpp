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
}

// Function to post to logger semaphore
void post_logger() {
    sem_post(&logger_sem);
}

// Function to post to LED semaphore
void post_led() {
    sem_post(&led_sem);
}

pthread_t rx_thread, detect_thread, log_thread, led_thread;

int main(int argc, char *argv[]) {
    openlog("PthreadService", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);
    syslog(LOG_INFO, "Starting DPDK packet sniffer with sequencer-controlled services...");

    // Initialize DPDK
    if (rte_eal_init(argc, argv) < 0) {
        syslog(LOG_ERR, "Failed to initialize DPDK EAL");
        return -1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create mbuf pool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        syslog(LOG_ERR, "Cannot create mbuf pool");
        return -1;
    }

    // Configure port
    struct rte_eth_conf port_conf = {};
    if (rte_eth_dev_configure(port_id, 1, 0, &port_conf) < 0 ||
        rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) < 0 ||
        rte_eth_dev_start(port_id) < 0) {
        syslog(LOG_ERR, "Failed to configure/start port %u", port_id);
        return -1;
    }

    // Create CSV output
    csv_file = fopen("packet_log.csv", "w");
    if (!csv_file) {
        syslog(LOG_ERR, "Failed to open CSV file");
        return -1;
    }
    fprintf(csv_file, "Timestamp,Source MAC,Destination MAC,Threat Status\n");

    // Create rings
    packet_ring = rte_ring_create(PACKET_RING_NAME, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    detected_ring = rte_ring_create(DETECTED_RING_NAME, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!packet_ring || !detected_ring) {
        syslog(LOG_ERR, "Failed to create rings");
        return -1;
    }

    // Start DPDK RX and intrusion detection threads (non-RMS)
    pthread_create(&rx_thread, nullptr, rx_thread_func, nullptr);
    pthread_create(&detect_thread, nullptr, intrusion_detection_thread_func, nullptr);

    // Start logger and LED threads (RMS-controlled)
    init_logger_led_threads(&log_thread, &led_thread);

    // Add LED and Logger to sequencer
    Sequencer sequencer;
    sequencer.addService(post_led,    1, 40, 5);    // LED service: 100ms
    sequencer.addService(post_logger, 3, 30, 10);   // Logger service: 1000ms

    // Start sequencer timer
    sequencer.startServices();

    std::this_thread::sleep_for(std::chrono::seconds(10));  // Run system for 10s

    // Stop sequencer and join threads
    sequencer.stopServices();
    pthread_join(rx_thread, nullptr);
    pthread_join(detect_thread, nullptr);
    join_logger_led_threads(log_thread, led_thread);

    fclose(csv_file);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();

    syslog(LOG_INFO, "Shutdown complete. Total packets received: %lu", total_rx);
    closelog();
    return 0;
}
