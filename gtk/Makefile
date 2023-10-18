CC=gcc
CFLAGS=-Ofast -march=native -mtune=native
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_CLIBS := $(shell pkg-config --libs gtk+-3.0)
SRCS=gtk-app.c
OBJS=$(SRCS:.c=.o)
TARGET=gtk-window

all: $(OBJS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(GTK_CLIBS) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(GTK_CLIBS) $(CFLAGS) -c $< -o $@

clean: 
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
