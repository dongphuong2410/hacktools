CC=gcc
CFLAGS=-ggdb -O0
LDFLAGS=-lnet

all: synflood

synflood: synflood.c
	$(CC) $^ $(CFLAGS) -o $@ $(LDFLAGS)

