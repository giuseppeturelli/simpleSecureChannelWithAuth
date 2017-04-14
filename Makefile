CC=g++
CFLAGS=-std=c++11 -Wall -g

LIB=libenvcry.so
LIBLDFLAGS=-shared
LIBCRYSRC=Envelope.cpp Signature.cpp CryptoStructures.cpp KeyManager.cpp
LIBCRYOBJ=$(LIBCRYSRC:.cpp=.o)

LDFLAGS=-L. -lcrypto -lboost_system -lpthread -lenvcry

CLIENTSRC=client.cpp
CLIENTOBJ=$(CLIENTSRC:.cpp=.o)
CLIENT=client

SERVERSRC=server.cpp
SERVEROBJ=$(SERVERSRC:.cpp=.o)
SERVER=server

all: $(LIB) $(CLIENT) $(SERVER)

$(LIB): $(LIBCRYOBJ)
	$(CC) $(LIBLDFLAGS) $(LIBCRYOBJ) -o $@
	
$(CLIENT): $(CLIENTOBJ)
	$(CC) $(CLIENTOBJ) $(LDFLAGS) -o $@

$(SERVER): $(SERVEROBJ)
	$(CC) $(SERVEROBJ) $(LDFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm -rf *o

