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
#include <ncurses.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
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

#define MAX_HISTORY 50

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
    uint64_t rx_tsc;
    uint64_t detect_tsc;
};

struct log_entry {
    char timestamp[32];
    char src_mac[32];
    char dst_mac[32];
    char threat_status[16];
    long detect_delay_ms;
    long log_delay_ms;
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
            struct detection_result *result = malloc(sizeof(struct detection_result));
            if (!result) {
                rte_pktmbuf_free(mbufs[i]);
                continue;
            }

            result->mbuf = mbufs[i];
            strncpy(result->threat_status, "UNKNOWN", sizeof(result->threat_status));
            result->rx_tsc = rte_get_tsc_cycles(); // Save RX time

            if (rte_ring_enqueue(packet_ring, result) < 0) {
                rte_pktmbuf_free(mbufs[i]);
                free(result);
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
        struct detection_result *result = NULL;
        if (rte_ring_dequeue(packet_ring, (void **)&result) == 0 && result != NULL) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(result->mbuf, struct rte_ether_hdr *);
            void *l3_hdr = (char *)eth_hdr + sizeof(struct rte_ether_hdr);
            uint8_t ip_proto = *((uint8_t *)l3_hdr + 9);
            if (ip_proto == 1) {
                strncpy(result->threat_status, "THREAT", sizeof(result->threat_status));
                threat_detected = true;
            } else {
                strncpy(result->threat_status, "SAFE", sizeof(result->threat_status));
            }

            result->detect_tsc = rte_get_tsc_cycles(); // Save detection completed time here

            if (rte_ring_enqueue(detected_ring, result) < 0) {
                rte_pktmbuf_free(result->mbuf);
                free(result);
            }
        }
    }
    return NULL;
}

FILE *init_csv_file() {
    FILE *csv_file = fopen("packet_logger.csv", "w");
    if (!csv_file) {
        perror("Failed to open CSV file for writing");
        exit(EXIT_FAILURE);
    }

    fprintf(csv_file, "Timestamp,Source MAC,Destination MAC,Threat Status,Detect Delay,Log Delay\n");
    fflush(csv_file);
    return csv_file;
}


void *logger_thread_func(void *arg) {
    (void)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(LOGGER_CORE_ID, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    set_realtime_priority(30);

    printf("[LOGGER] Thread running on core %d\n", LOGGER_CORE_ID);

    uint64_t tsc_hz = rte_get_tsc_hz(); // Get TSC frequency once

    FILE *csv_file = init_csv_file();

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);
    nodelay(stdscr, TRUE); // Non-blocking getch
    start_color();

    init_pair(1, COLOR_RED, COLOR_BLACK);   // Red for threats
    init_pair(2, COLOR_GREEN, COLOR_BLACK); // Green for safe

    struct log_entry history[MAX_HISTORY];
    int history_count = 0;

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

            time_t now_sec = time(NULL);
            struct tm *tm_info = localtime(&now_sec);
            char timestamp[32];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

            uint64_t now_tsc = rte_get_tsc_cycles();

            uint64_t detect_delay_cycles = result->detect_tsc - result->rx_tsc;
            uint64_t log_delay_cycles = now_tsc - result->detect_tsc;

            long detect_delay_ms = (detect_delay_cycles * 1000) / tsc_hz;
            long log_delay_ms = (log_delay_cycles * 1000) / tsc_hz;

            // Save to history
            if (history_count >= MAX_HISTORY) {
                memmove(&history[0], &history[1], sizeof(struct log_entry) * (MAX_HISTORY - 1));
                history_count = MAX_HISTORY - 1;
            }

            strncpy(history[history_count].timestamp, timestamp, sizeof(timestamp));
            strncpy(history[history_count].src_mac, src_mac, sizeof(src_mac));
            strncpy(history[history_count].dst_mac, dst_mac, sizeof(dst_mac));
            strncpy(history[history_count].threat_status, result->threat_status, sizeof(result->threat_status));
            history[history_count].detect_delay_ms = detect_delay_ms;
            history[history_count].log_delay_ms = log_delay_ms;
            history_count++;

            // Write immediately to CSV
            fprintf(csv_file, "%s,%s,%s,%s,%ldms,%ldms\n",
                    timestamp, src_mac, dst_mac, result->threat_status,
                    detect_delay_ms, log_delay_ms);
            fflush(csv_file);

            rte_pktmbuf_free(result->mbuf);
            free(result);
        }

        // Draw history
        clear();
        mvprintw(0, 0, "Timestamp              SourceMAC           DestinationMAC      Threat    DetectDelay  LogDelay");
        for (int i = 0; i < history_count; i++) {
            if (strcmp(history[i].threat_status, "THREAT") == 0) {
                attron(COLOR_PAIR(1));
            } else {
                attron(COLOR_PAIR(2));
            }

            mvprintw(i + 1, 0, "%s  %s -> %s     %s         %ldms        %ldms",
                     history[i].timestamp,
                     history[i].src_mac,
                     history[i].dst_mac,
                     history[i].threat_status,
                     history[i].detect_delay_ms,
                     history[i].log_delay_ms);

            attroff(COLOR_PAIR(1));
            attroff(COLOR_PAIR(2));
        }

        refresh();
        usleep(50000); // Small sleep to avoid 100% CPU
    }

    fclose(csv_file);
    endwin();
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


