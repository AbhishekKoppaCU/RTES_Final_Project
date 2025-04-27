#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> // ETH_P_IP
#include <netpacket/packet.h>
#include <net/if.h>
#include <time.h>

volatile int force_quit = 0;

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

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Bind to eth0 interface only
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP); // Only IP traffic
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
    fprintf(csv_file, "Timestamp_us,Bytes_Received\n");

    printf("Non-DPDK (AF_PACKET, eth0, IP traffic) Receiver started...\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (!force_quit) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n > 0) {
            uint64_t timestamp = get_timestamp_us();
            fprintf(csv_file, "%lu,%d\n", timestamp, n);
            fflush(csv_file);
        }
    }

    fclose(csv_file);
    close(sockfd);
    printf("Non-DPDK Receiver exiting...\n");
    return 0;
}
