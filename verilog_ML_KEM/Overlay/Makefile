# Build the C-bypass fast-poll shared library on the KR260 board.
#   make           # build libmlkemfast.so
#   make clean     # remove build artifacts

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -fPIC
LDFLAGS ?= -shared

TARGET  := libmlkemfast.so
SOURCES := ml_kem_fast_poll.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: clean
