CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
CEXTRALIBS=-I /usr/include/openssl
CEXTRAFLAGS=-lssl -lcrypto
SRCS=main.c encryption.c decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=aes

all: $(OBJS)
	$(CC) $(CFLAGS) $(CEXTRAFLAGS) $(OBJS) -o $(TARGET) $(CEXTRALIBS)

%.o: %.
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean
