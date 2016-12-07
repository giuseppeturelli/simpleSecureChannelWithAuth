CC=g++
CFLAGS=-std=c++11 -Wall -g

all: client server

Crypto.o: Crypto.cpp Crypto.h BaseSixtyFour.cpp BaseSixtyFour.h
	$(CC) $(CFLAGS) Crypto.cpp BaseSixtyFour.cpp -c

server.o: server.cpp Crypto.h BaseSixtyFour.h
	$(CC) $(CFLAGS) server.cpp -c

client.o: client.cpp Crypto.h BaseSixtyFour.h
	$(CC) $(CFLAGS) client.cpp -c

server: server.o Crypto.o BaseSixtyFour.o
	$(CC) $(CFLAGS) server.o Crypto.o BaseSixtyFour.o -lcrypto -lboost_system -lpthread -o server

client: client.o Crypto.o BaseSixtyFour.o
	$(CC) $(CFLAGS) client.o Crypto.o BaseSixtyFour.o -lcrypto -lboost_system -lpthread -o client

test: test.o Crypto.o BaseSixtyFour.o
	$(CC) $(CFLAGS) test.o Crypto.o BaseSixtyFour.o -lcrypto -o test

clean:
	rm -rf *o
