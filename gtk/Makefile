CC=gcc
CFLAGS=-Ofast -march=native -mtune=native
SRCS=pruebasGtk.c gui.c dialogs.c
TARGET=pruebasGtk
DEBUG_TARGET=pruebasGt-debug
GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(GTK_EXTRA) -DTESTING
	$(CC) $(CFLAGS) $(SRCS) -o $(DEBUG_TARGET) $(GTK_EXTRA) -DTESTING -DMODULE_DEBUG

clean:
	rm -f $(OBJS) $(TARGET) $(DEBUG_TARGET)

.PHONY: clean
