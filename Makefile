CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
SRCS=main.c ./openSSL/encryption.c ./openSSL/decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=aes
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
#GTK_EXTRA := $(shell pkg-config --cflags --libs gtk+-3.0)

# --- Opciones de compilacion
all: term gui

term: $(OBJS) # Compilar solo la version de terminal
	$(CC) $(OPENSSLLIBS) $(OBJS) -o $(TARGET) $(OPENSSLFLAGS) $(KYBER_LIBS)

gui: $(OBJS) # Compilar solo la version con gui de GTK
	$(CC) $(OPENSSLLIBS) $(OBJS) -o $(TARGET_GUI) $(OPENSSLFLAGS) $(KYBER_LIBS) $(GTK_EXTRA) -DGTK_GUI

clean:
	rm -rf $(OBJS)\
		$(TARGET)\
		$(TARGET_GUI)

.PHONY: clean term gui
