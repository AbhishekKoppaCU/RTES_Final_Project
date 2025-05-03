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
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "packet_logger.h"
#include "packet_db.h"



#define RX_CORE_ID 1
#define DETECTION_CORE_ID 2
#define LOGGER_CORE_ID 3

#define MAX_HISTORY 50

#define CLIENT_PORT 12345  
#define SERVER_PORT 9999   


volatile bool force_quit = false;
struct rte_mempool *mbuf_pool;
struct rte_ring *packet_ring;
struct rte_ring *detected_ring;
FILE *csv_file;
uint16_t port_id = 0;
uint64_t total_rx = 0;

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
    if (signum == SIGINT || signum == SIGTERM || signum == SIGSEGV || signum == SIGABRT) {
        force_quit = true;
        syslog(LOG_INFO,"\nSignal %d received, exiting...\n", signum);
        endwin();
    }
}

void rx_service() {

    struct rte_mbuf *mbufs[BURST_SIZE]; 
    syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());
    while(!force_quit){
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
}



const char* lookup_interest(const char* name) {
    for (int i = 0; i < MAX_PEOPLE; i++) {
        if (strncmp(name, database[i].name, MAX_NAME_LEN) == 0) {
            return database[i].interest;
        }
    }
    return NULL;
}

void detect_service() {
    syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());

    while (!force_quit) {
        struct detection_result *result = NULL;
        if (rte_ring_dequeue(packet_ring, (void **)&result) == 0 && result != NULL) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(result->mbuf, struct rte_ether_hdr *);
            void *l3_hdr = (char *)eth_hdr + sizeof(struct rte_ether_hdr);
            struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;

            uint8_t ip_proto = ipv4_hdr->next_proto_id;

            if (ip_proto == IPPROTO_ICMP) {
                strncpy(result->threat_status, "THREAT", sizeof(result->threat_status));
            } else {
                strncpy(result->threat_status, "SAFE", sizeof(result->threat_status));

                if (ip_proto == IPPROTO_UDP) {
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
                    char *payload = (char *)udp_hdr + sizeof(struct rte_udp_hdr);
                    int payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

                    if (payload_len > 0 && payload_len < 256) {
                        char type[16] = {0}, resource[64] = {0};
                        sscanf(payload, "type=%15[^;];resource=%63s", type, resource);

                        if (strcmp(type, "GET") == 0) {
                            const char *interest = lookup_interest(resource);
                            if (interest) {
                                syslog(LOG_INFO, "[IDS] Valid GET: name=%s, interest=%s", resource, interest);

                                int sock = socket(AF_INET, SOCK_DGRAM, 0);
                                if (sock < 0) {
                                    syslog(LOG_ERR, "[IDS] Failed to create socket: %s", strerror(errno));
                                } else {
                                    struct sockaddr_in client_addr;
                                    memset(&client_addr, 0, sizeof(client_addr));
                                    client_addr.sin_family = AF_INET;
                                    client_addr.sin_port = htons(CLIENT_PORT);
                                    client_addr.sin_addr.s_addr = ipv4_hdr->src_addr;

                                    char reply[128];
                                    snprintf(reply, sizeof(reply), "Interest: %s", interest);

                                    char ip_str[INET_ADDRSTRLEN];
                                    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
                                    syslog(LOG_INFO, "[IDS] Sending UDP reply to %s:%d — \"%s\"",
                                           ip_str, CLIENT_PORT, reply);

                                    ssize_t sent = sendto(sock, reply, strlen(reply), 0,
                                                          (struct sockaddr *)&client_addr, sizeof(client_addr));
                                    if (sent < 0) {
                                        syslog(LOG_ERR, "[IDS] sendto() failed: %s", strerror(errno));
                                    }

                                    close(sock);
                                }
                            }
                        } else if (strcmp(type, "SET") == 0) {
                            syslog(LOG_INFO, "[IDS] Ignoring SET request for now");
                        }
                    }
                }
            }

            result->detect_tsc = rte_get_tsc_cycles();

            if (rte_ring_enqueue(detected_ring, result) < 0) {
                rte_pktmbuf_free(result->mbuf);
                free(result);
            }
        }
    }
}


FILE *init_csv_file() {
    FILE *csv_file = fopen("packet_logger.csv", "w");
    if (!csv_file) {
        syslog(LOG_ERR, "Failed to open CSV file for writing");
        exit(EXIT_FAILURE);
    }

    fprintf(csv_file, "Timestamp,Source MAC,Destination MAC,Threat Status,Detect Delay,Log Delay\n");
    fflush(csv_file);
    return csv_file;
}


void logger_service() {
    static bool initialized = false;
    static FILE *csv_file = NULL;
    static uint64_t tsc_hz = 0;
    static struct log_entry history[MAX_HISTORY];
    static int history_count = 0;
    static uint64_t last_refresh_time = 0;

    if (!initialized) {
        syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());
        tsc_hz = rte_get_tsc_hz();
        csv_file = fopen("packet_logger.csv", "w");
        if (csv_file) {
            fprintf(csv_file, "Timestamp,Source MAC,Destination MAC,Threat Status,Detect Delay,Log Delay\n");
            fflush(csv_file);
        }
        initscr();
        cbreak();
        noecho();
        curs_set(FALSE);
        nodelay(stdscr, TRUE);
        start_color();
        init_pair(1, COLOR_RED, COLOR_BLACK);
        init_pair(2, COLOR_GREEN, COLOR_BLACK);
        initialized = true;
    }

    struct detection_result *result = NULL;
    if (rte_ring_dequeue(detected_ring, (void **)&result) == 0 && result != NULL) {
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

        if (csv_file) {
            fprintf(csv_file, "%s,%s,%s,%s,%ldms,%ldms\n",
                    timestamp, src_mac, dst_mac, result->threat_status,
                    detect_delay_ms, log_delay_ms);
            fflush(csv_file);
        }

        rte_pktmbuf_free(result->mbuf);
        free(result);
    }

    // Refresh ncurses screen every 100ms
    uint64_t now = rte_get_timer_cycles();
    uint64_t hz = rte_get_timer_hz();
    if ((now - last_refresh_time) > (hz / 1)) { // 10ms
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
        last_refresh_time = now;
    }
    if (force_quit) {
    endwin(); // Properly reset terminal
    }
}





void led_service() {
    static bool initialized = false;
    static int blink_counter = 0;
    
    if (!initialized) {
        syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());
        initialized = true;
        //printf("[LED] LED service initialized\n");
    }

   if (!threat_detected) {
        blink_counter++;
        if (blink_counter >= 10) {
            blink_counter = 0;
            //syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());
    } else {
        //syslog(LOG_INFO, "[%s] Thread running on core %d", __func__, sched_getcpu());
    }
}
}

