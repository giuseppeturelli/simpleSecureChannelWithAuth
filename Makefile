CC=g++
CFLAGS=-std=c++11 -Wall -g

all: client server

Crypto.o: Crypto.cpp Crypto.h
	$(CC) $(CFLAGS) Crypto.cpp -c

server.o: server.cpp Crypto.h
	$(CC) $(CFLAGS) server.cpp -c

client.o: client.cpp Crypto.h
	$(CC) $(CFLAGS) client.cpp -c

server: server.o Crypto.o
	$(CC) $(CFLAGS) server.o Crypto.o -lcrypto -lboost_system -lpthread -o server

client: client.o Crypto.o
	$(CC) $(CFLAGS) client.o Crypto.o -lcrypto -lboost_system -lpthread -o client

clean:
	rm -rf *o
