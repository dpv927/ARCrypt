CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
CEXTRAFLAGS=-lssl -lcrypto
CEXTRALIBS=-I /usr/include/openssl
SRCS=main.c ./openSSL/encryption.c ./openSSL/decryption.c
OBJS=$(SRCS:.c=.o)
TARGET=aes

# ----- Librerias de Kyber ----- 
LIB_PATH = ./libs
#LIBS = -L$(LIB_PATH) -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
#LIBS = -L$(LIB_PATH) -lpqcrystals_kyber512-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#LIBS = -L$(LIB_PATH) -lpqcrystals_kyber768_ref -lpqcrystals_fips202_ref
#LIBS = -L$(LIB_PATH) -lpqcrystals_kyber768-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
LIBS = -L$(LIB_PATH) -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref
#LIBS = -L$(LIB_PATH) -lpqcrystals_kyber1024-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref

all: $(OBJS)
	$(CC) $(CEXTRALIBS) $(OBJS) -o $(TARGET) $(CEXTRAFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean
