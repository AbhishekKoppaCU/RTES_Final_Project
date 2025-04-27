/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "packet_logger.h"

#define RX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PACKET_RING_NAME "PACKET_RING"
#define DETECTED_RING_NAME "DETECTED_RING"

#define RX_CORE_ID 1
#define DETECTION_CORE_ID 2
#define LOGGER_CORE_ID 3

volatile bool force_quit = false;
struct rte_mempool *mbuf_pool;
struct rte_ring *packet_ring;
struct rte_ring *detected_ring;
FILE *csv_file;
uint16_t port_id = 0;
uint64_t total_rx = 0;

sem_t led_sem;
sem_t logger_sem;

volatile bool threat_detected = false;

struct detection_result {
    struct rte_mbuf *mbuf;
    char threat_status[16]; // "SAFE" or "THREAT"
};

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
        printf("\nSignal %d received, exiting...\n", signum);

        // Unblock any threads waiting on semaphores
        sem_post(&led_sem);
        sem_post(&logger_sem);
    }
}


static void set_realtime_priority(int priority) {
    struct sched_param param;
    param.sched_priority = priority;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
        perror("Failed to set real-time priority");
    }
}

void *rx_thread_func(void *arg) {
    (void)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(RX_CORE_ID, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    set_realtime_priority(80);

    struct rte_mbuf *mbufs[BURST_SIZE];
    printf("[RX] Thread running on core %d\n", RX_CORE_ID);

    while (!force_quit) {
        const uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, BURST_SIZE);
        total_rx += nb_rx;
        for (int i = 0; i < nb_rx; i++) {
            if (rte_ring_enqueue(packet_ring, mbufs[i]) < 0) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return NULL;
}

void *intrusion_detection_thread_func(void *arg) {
    (void)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(DETECTION_CORE_ID, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    set_realtime_priority(60);

    printf("[DETECTION] Thread running on core %d\n", DETECTION_CORE_ID);

    while (!force_quit) {
        struct rte_mbuf *mbuf = NULL;
        if (rte_ring_dequeue(packet_ring, (void **)&mbuf) == 0 && mbuf != NULL) {
            struct detection_result *result = malloc(sizeof(struct detection_result));
            result->mbuf = mbuf;

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            void *l3_hdr = (char *)eth_hdr + sizeof(struct rte_ether_hdr);
            uint8_t ip_proto = *((uint8_t *)l3_hdr + 9);
            if (ip_proto == 1) {
                strncpy(result->threat_status, "THREAT", sizeof(result->threat_status));
                threat_detected = true;
            } else {
                strncpy(result->threat_status, "SAFE", sizeof(result->threat_status));
            }

            if (rte_ring_enqueue(detected_ring, result) < 0) {
                rte_pktmbuf_free(mbuf);
                free(result);
            }
        }
    }
    return NULL;
}

void *logger_thread_func(void *arg) {
    (void)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(LOGGER_CORE_ID, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    set_realtime_priority(30);

    printf("[LOGGER] Thread running on core %d\n", LOGGER_CORE_ID);

    while (!force_quit) {
        sem_wait(&logger_sem);

        while (true) {
            struct detection_result *result = NULL;
            if (rte_ring_dequeue(detected_ring, (void **)&result) < 0 || result == NULL)
                break;

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(result->mbuf, struct rte_ether_hdr *);
            char src_mac[32], dst_mac[32];
            rte_ether_format_addr(src_mac, sizeof(src_mac), &eth_hdr->src_addr);
            rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth_hdr->dst_addr);

            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char timestamp[32];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

            fprintf(csv_file, "%s,%s,%s,%s\n", timestamp, src_mac, dst_mac, result->threat_status);
            fflush(csv_file);

            rte_pktmbuf_free(result->mbuf);
            free(result);
        }
    }
    return NULL;
}


void *led_thread_func(void *arg) {
    (void)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(LOGGER_CORE_ID, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    set_realtime_priority(40);

    int blink_counter = 0;
    
    printf("[LED] Thread running on core %d\n", LOGGER_CORE_ID);

    while (!force_quit) {
        sem_wait(&led_sem);

        if (!threat_detected) {
            blink_counter++;
            if (blink_counter >= 10) {
                printf("[LED] Blinking slowly (SAFE mode)\n");
                blink_counter = 0;
            }
        } else {
            printf("[LED] Blinking rapidly (THREAT detected)\n");
        }
    }
    return NULL;
}

void init_logger_led_threads(pthread_t *log_thread, pthread_t *led_thread) {
    sem_init(&led_sem, 0, 0);
    sem_init(&logger_sem, 0, 0);

    pthread_create(log_thread, NULL, logger_thread_func, NULL);
    pthread_create(led_thread, NULL, led_thread_func, NULL);
}

void join_logger_led_threads(pthread_t log_thread, pthread_t led_thread) {
    pthread_join(log_thread, NULL);
    pthread_join(led_thread, NULL);
}


