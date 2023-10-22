CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
CEXTRAFLAGS=-lssl -lcrypto
CEXTRALIBS=-I /usr/include/openssl
SRCS=main.c ./openSSL/encryption.c ./openSSL/decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=aes

all: $(OBJS)
	$(CC) $(CEXTRALIBS) $(OBJS) -o $(TARGET) $(CEXTRAFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean
