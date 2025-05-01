#include "packet_logger.h"
#include "packet_db.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sched.h>
#include <stdbool.h>

Person database[MAX_PEOPLE] = {
    {"Parth", "Dancing"},
    {"Jainil", "Cycling"},
    {"Varsani", "Astrology"},
    {"Nadgir", "Cooking"},
    {"Koppa", "Sports"},
    {"Nalin", "Sleeping"},
    {"Karthik", "Running"},
    {"Abhirath", "Chess"},
    {"Aditya", "Swimming"},
    {"Induja", "Coding"}
};

static void handle_get(int client_fd) {
    char html[2048];
    char table[1024] = "";

    for (int i = 0; i < MAX_PEOPLE; i++) {
        char row[256];
        snprintf(row, sizeof(row),
            "<tr><td><input name=\"name%d\" value=\"%s\"></td>"
            "<td><input name=\"interest%d\" value=\"%s\"></td></tr>\n",
            i, database[i].name, i, database[i].interest);
        strcat(table, row);
    }

    snprintf(html, sizeof(html),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h2>Server Database</h2>"
        "<form method=\"POST\">"
        "<table border=1><tr><th>Name</th><th>Interest</th></tr>"
        "%s</table><br><input type=\"submit\"></form></body></html>", table);

    send(client_fd, html, strlen(html), 0);
}

static void handle_post(int client_fd, const char *body) {
    for (int i = 0; i < MAX_PEOPLE; i++) {
        char key_name[16], key_interest[20];
        snprintf(key_name, sizeof(key_name), "name%d=", i);
        snprintf(key_interest, sizeof(key_interest), "interest%d=", i);

        char *n = strstr(body, key_name);
        char *v = strstr(body, key_interest);

        if (n && v) {
            sscanf(n + strlen(key_name), "%31[^&]", database[i].name);
            sscanf(v + strlen(key_interest), "%31[^&]", database[i].interest);
        }
    }

    // Respond with redirect
    const char *resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
    send(client_fd, resp, strlen(resp), 0);
}

void server_service() {
    static int server_fd = -1;
    static bool initialized = false;

    if (!initialized) {
        struct sockaddr_in address;
        int opt = 1;

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            syslog(LOG_ERR, "Socket creation failed");
            exit(EXIT_FAILURE);
        }

        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
        fcntl(server_fd, F_SETFL, O_NONBLOCK);

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(8080);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
            listen(server_fd, 5) < 0) {
            syslog(LOG_ERR, "Bind or Listen failed");
            exit(EXIT_FAILURE);
        }

        initialized = true;
    }

    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_address, &client_addrlen);
    if (client_fd < 0) return;

    char buffer[4096] = {0};
    int len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (len <= 0) { close(client_fd); return; }

    if (strncmp(buffer, "GET", 3) == 0) {
        handle_get(client_fd);
    } else if (strncmp(buffer, "POST", 4) == 0) {
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;
            handle_post(client_fd, body);
        }
    }

    shutdown(client_fd, SHUT_WR);
    close(client_fd);
}
