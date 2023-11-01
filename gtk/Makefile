CC=gcc
CFLAGS=-Ofast -march=native -mtune=native
SRCS=main.c gui.c dialogs.c
OMP=-fopenmp
TARGET=gtk-window
DEBUG_TARGET=gtk-debug
GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)


all:
	#gcc gtk-app.c -o gtk-window $(shell pkg-config --cflags --libs gtk+-3.0)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(GTK_EXTRA) $(OMP)
	$(CC) $(CFLAGS) $(SRCS) -o $(DEBUG_TARGET) $(GTK_EXTRA) $(OMP) -DMODULE_DEBUG

clean: 
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
