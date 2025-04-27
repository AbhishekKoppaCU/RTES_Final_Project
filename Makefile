# Compiler configuration
CXX = g++
CC = gcc
CFLAGS = -O3 -Wall -Wextra -march=native
CXXFLAGS = -O3 -Wall -Wextra -std=c++23
PKGCONF = pkg-config
DPDK_CFLAGS = $(shell $(PKGCONF) --cflags libdpdk)
DPDK_LDLIBS = $(shell $(PKGCONF) --libs libdpdk)

# Sources and targets
C_SOURCES = main.c
CPP_SOURCES = Sequencer.cpp
OBJECTS = main.o Sequencer.o

TARGET = packet_logger

# Extra libraries
EXTRA_LDLIBS = -lpthread -lncurses

all: $(TARGET)

# Build C object file
main.o: main.c
	$(CC) $(CFLAGS) $(DPDK_CFLAGS) -c $< -o $@

# Build C++ object file
Sequencer.o: Sequencer.cpp
	$(CXX) $(CXXFLAGS) $(DPDK_CFLAGS) -c $< -o $@

# Link final executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(DPDK_LDLIBS) $(EXTRA_LDLIBS)

clean:
	rm -f $(TARGET) *.o packet_log.csv
