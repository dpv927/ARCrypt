CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
SRCS=./pruebasOpenssl.c encryption.c decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=pruebas

# --- Flags OpenSSL ---
OPENSSLLIBS=-I /usr/include/openssl
OPENSSLFLAGS=-lssl -lcrypto

all: $(OBJS)
	$(CC) $(OPENSSLLIBS) $(OBJS) -o $(TARGET) $(OPENSSLFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean
