CC = gcc
CFLAGS = -O3 -Wall -Wextra -march=native
PKGCONF = pkg-config
DPDK_CFLAGS = $(shell $(PKGCONF) --cflags libdpdk)
DPDK_LDLIBS = $(shell $(PKGCONF) --libs libdpdk)

all: packet_logger

packet_logger: main.c
	$(CC) $(CFLAGS) $(DPDK_CFLAGS) $^ -o $@ $(DPDK_LDLIBS)

clean:
	rm -f packet_logger packet_log.csv
