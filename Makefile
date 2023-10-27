CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
SRCS=main.c ./openSSL/encryption.c ./openSSL/decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=aes

# --- Flags OpenSSL ---
OPENSSLLIBS=-I /usr/include/openssl
OPENSSLFLAGS=-lssl -lcrypto

# --- Librerias de Kyber --- 
#KYBER_LIBS = -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber768_ref -lpqcrystals_fips202_ref
KYBER_LIBS = -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber512-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber768-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber1024-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref

all: $(OBJS)
	$(CC) $(OPENSSLLIBS) $(OBJS) -o $(TARGET) $(OPENSSLFLAGS) $(KYBER_LIBS)

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean