CC=gcc
CFLAGS=-Ofast -march=native -mtune=native
SRCS=gtk-app.c main_window.c
TARGET=gtk-window
GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)

all:
	#gcc gtk-app.c -o gtk-window $(shell pkg-config --cflags --libs gtk+-3.0)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(GTK_EXTRA)

clean: 
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
