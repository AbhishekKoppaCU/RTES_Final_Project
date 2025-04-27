#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <time.h>

#define CAPTURE_DURATION_SEC 30

volatile int force_quit = 0;
static time_t start_time;

void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        force_quit = 1;
}

static uint64_t get_timestamp_us()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

int main()
{
    int sockfd;
    char buffer[2048];

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set socket timeout of 1 second
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eth0");

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    FILE *csv_file = fopen("non_dpdk_packet_log.csv", "w");
    if (!csv_file) {
        perror("Failed to open CSV file");
        close(sockfd);
        return -1;
    }
    fprintf(csv_file, "Timestamp_us,Source MAC,Destination MAC\n");

    printf("Non-DPDK (AF_PACKET, eth0) Receiver started...\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    start_time = time(NULL);

    while (!force_quit) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n > 0) {
            struct ethhdr *eth = (struct ethhdr *)buffer;

            char src_mac[18], dst_mac[18];
            snprintf(src_mac, sizeof(src_mac),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth->h_source[0], eth->h_source[1], eth->h_source[2],
                     eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            snprintf(dst_mac, sizeof(dst_mac),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                     eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            uint64_t timestamp = get_timestamp_us();
            fprintf(csv_file, "%lu,%s,%s\n", timestamp, src_mac, dst_mac);
            fflush(csv_file);
        }
        // Check timeout and stop after 30 sec
        if (time(NULL) - start_time >= CAPTURE_DURATION_SEC) {
            force_quit = 1;
        }
    }

    fclose(csv_file);
    close(sockfd);
    printf("Non-DPDK Receiver exiting...\n");
    return 0;
}
