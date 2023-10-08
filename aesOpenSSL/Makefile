CC=g++
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
CEXTRAFLAGS=-lssl -lcrypto
SRCS=main.cpp encrypter.cpp decrypter.cpp
OBJS=$(SRCS:.c=.o)
TARGET=aes

all: $(OBJS)
	$(CC) $(CFLAGS) $(CEXTRAFLAGS) $(OBJS) -o $(TARGET)

%.o: %.
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o
	rm -rf $(TARGET)

.PHONY: clean
