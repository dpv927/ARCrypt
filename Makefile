CC=gcc
CFLAGS=-Ofast -march=native -mtune=native

# --- Archivos a compilar
OPENSSL_SRCS = ./openSSL/encryption.c ./openSSL/decryption.c ./openSSL/files.c ./openSSL/hash.c ./openSSL/iv_kdf.c ./openSSL/superkey.c
GUI_SRCS = gui_mode.c ./gtk/dialogs.c ./gtk/gui.c
TERM_SRCS = term_mode.c 
TARGET_TERM=aes
TARGET_GUI=aes-gui

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
GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)

# --- Opciones de compilacion
all: term # gui

term: 
	$(CC) $(OPENSSLLIBS) main.c $(OPENSSL_SRCS) $(TERM_SRCS) -o $(TARGET_TERM) $(OPENSSLFLAGS) $(CFLAGS)

gui: 
	$(CC) $(OPENSSLLIBS) main.c $(OPENSSL_SRCS) $(GUI_SRCS) -o $(TARGET_GUI) $(OPENSSLFLAGS) $(GTK_EXTRA) $(CFLAGS) -DGTK_GUI

clean:
	rm -rf *.o
	rm -rf ./openSSL/*.o
	rm -rf ./gtk/*.o
	rm -rf $(TARGET_TERM)
	rm -rf $(TARGET_GUI)

.PHONY: clean term gui
