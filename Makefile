CC=gcc
CFLAGS=-Ofast -march=native -mtune=native -Wno-unused-result

# --- Archivos a compilar
OPENSSL_SRCS = ./openSSL/encryption.c ./openSSL/decryption.c ./openSSL/files.c ./openSSL/hash.c ./openSSL/superkey.c

TERM_SRCS = term_mode.c 
TERM_OBJS = $(OPENSSL_SRCS:.c=.o) $(TERM_SRCS:.c=.o)
TARGET_TERM=arcrypt

GUI_SRCS = gui_mode.c ./gtk/dialogs.c ./gtk/gui.c
GUI_OBJS = $(OPENSSL_SRCS:.c=.o) $(GUI_SRCS:.c=.o)
TARGET_GUI=arcrypt-gui

# --- Flags OpenSSL ---
OPENSSLLIBS=-I /usr/include/openssl
OPENSSLFLAGS=-lssl -lcrypto

# --- Librerias de Kyber --- 
#KYBER_LIBS = -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber768_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber512-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber768-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber1024-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref

# --- Librerias y flags de GTK
# GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)

# --- Opciones de compilacion
default: term # Se asume que no todo el mundo tiene librerias de GTK3.0 
all: term gui # Ejecutar 'make all' para generar los ejecutables de ambos modos

term-objs: $(TERM_OBJS) main.o
	$(CC) $^ -o $(TARGET_TERM) $(OPENSSLFLAGS) $(CFLAGS)

term: term-objs # Compilar el programa en modo terminal (Sin GUI).  
	$(CC) $(OPENSSLLIBS) main.c $(TERM_OBJS) -o $(TARGET_TERM) $(OPENSSLFLAGS) $(CFLAGS) -g

gui-objs: $(GUI_OBJS) main.o
	$(CC) $^ -o $(OPENSSLFLAGS) $(GTK_EXTRA) $(CFLAGS) -DGTK_GUI

gui: gui-objs # Compilar el programa en modo GTK (Con GUI).  
	$(CC) $(OPENSSLLIBS) main.c $(GUI_OBJS) -o $(TARGET_GUI) $(OPENSSLFLAGS) $(GTK_EXTRA) $(CFLAGS) -DGTK_GUI

clean:
	rm -rf *.o
	rm -rf ./openSSL/*.o
	rm -rf ./gtk/*.o
	rm -rf $(TARGET_TERM)
	rm -rf $(TARGET_GUI)

.PHONY: clean term gui
