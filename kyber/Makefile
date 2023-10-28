CC=gcc
CFLAGS=-Wall -Wextra -Ofast -march=native -mtune=native
SRCS=main.c
OBJS=$(SRCS:.c=.o)
TARGET=exec

# --- Librerias de Kyber --- 
#KYBER_LIBS = -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber768_ref -lpqcrystals_fips202_ref
KYBER_LIBS = -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref
#KYBER_LIBS = -lpqcrystals_kyber512-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber768-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
#KYBER_LIBS = -lpqcrystals_kyber1024-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref

all: $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(KYBER_LIBS)

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: clean
