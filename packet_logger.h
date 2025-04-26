#pragma once
#include <stdbool.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Shared DPDK globals
extern volatile bool force_quit;
extern struct rte_mempool *mbuf_pool;
extern struct rte_ring *packet_ring;
extern struct rte_ring *detected_ring;
extern FILE *csv_file;
extern uint16_t port_id;
extern uint64_t total_rx;

// DPDK constants
#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PACKET_RING_NAME "PACKET_RING"
#define DETECTED_RING_NAME "DETECTED_RING"

#define RX_CORE_ID 1
#define DETECTION_CORE_ID 2
#define LOGGER_CORE_ID 3

// Semaphores for LED and Logger
extern sem_t led_sem;
extern sem_t logger_sem;

// Shared threat flag
extern volatile bool threat_detected;

// Thread prototypes
void *rx_thread_func(void *arg);
void *intrusion_detection_thread_func(void *arg);
void *logger_thread_func(void *arg);
void *led_thread_func(void *arg);

// Wrapper APIs for LED/Logger threads
void init_logger_led_threads(pthread_t *log_thread, pthread_t *led_thread);
void join_logger_led_threads(pthread_t log_thread, pthread_t led_thread);

// Signal handler
void signal_handler(int signum);

#ifdef __cplusplus
}
#endif
