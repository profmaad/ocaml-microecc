MICROECC_DIR=micro-ecc

CC=gcc
CFLAGS=-Wall -Werror -fpic -O2
LDFLAGS=-shared

all: libmicroecc_secp256k1.so

uECC_secp256k1.o: $(MICROECC_DIR)/uECC.c $(MICROECC_DIR)/uECC.h
	$(CC) $(CFLAGS) -c -DuECC_CURVE=uECC_secp256k1 -o $@ $<

libmicroecc_secp256k1.so: uECC_secp256k1.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -rf uECC_secp256k1.o
distclean: clean
	rm -rf libmicroecc_secp256k1.so
