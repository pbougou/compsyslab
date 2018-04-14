###################################################
#
# Makefile
# Simple example for cryptodev-linux
#
# Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CRYPTODEVDIR=$(HOME)/cryptodev/cryptodev-linux-1.6

CFLAGS = -Wall -I$(CRYPTODEVDIR) -Wno-pointer-sign 
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

BINS = server client

all: $(BINS)

server: server.c

client: client.c crypt.h

clean:
	rm -f *.o *~ $(BINS)
