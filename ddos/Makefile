CC=gcc
CFLAGS=-ggdb -O0
LDFLAGS=-lnet

all: synflood reset_hijack

synflood: synflood.c
	$(CC) $^ $(CFLAGS) -o $@ $(LDFLAGS)

reset_hijack: reset_hijack.c
	$(CC) $^ $(CFLAGS) -o $@ $(LDFLAGS)

