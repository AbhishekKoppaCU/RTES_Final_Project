// server_service.c

#include "packet_logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

void server_service() {
    static int server_fd = -1;
    static bool initialized = false;

    if (!initialized) {
        syslog(LOG_INFO, "[SERVER] Initializing local web server on core %d", sched_getcpu());

        struct sockaddr_in address;
        int opt = 1;
        int addrlen = sizeof(address);

        // Create socket
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            syslog(LOG_ERR, "[SERVER] Socket creation failed");
            exit(EXIT_FAILURE);
        }

        // Allow reuse of address/port
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            syslog(LOG_ERR, "[SERVER] Setsockopt failed");
            exit(EXIT_FAILURE);
        }

        // Set non-blocking
        fcntl(server_fd, F_SETFL, O_NONBLOCK);

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0
        address.sin_port = htons(8080);         // Port 8080

        // Bind
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            syslog(LOG_ERR, "[SERVER] Bind failed");
            exit(EXIT_FAILURE);
        }

        // Listen
        if (listen(server_fd, 5) < 0) {
            syslog(LOG_ERR, "[SERVER] Listen failed");
            exit(EXIT_FAILURE);
        }

        initialized = true;
    }

    // Each time service releases: check if connection is pending
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);
    int new_socket = accept(server_fd, (struct sockaddr *)&client_address, &client_addrlen);

    if (new_socket >= 0) {
        // Client connected
        const char *response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 23\r\n"
            "\r\n"
            "Welcome to Company LAN";

        send(new_socket, response, strlen(response), 0);
        close(new_socket);
    }
    // else: no pending connections (normal)
}
