CC=g++
CFLAGS=-std=c++11 -Wall -g
LDFLAGS=-L. -lcrypto -lboost_system -lpthread -lenvcry
SOURCES=Envelope.cpp Signature.cpp CryptoStructures.cpp KeyManager.cpp client.cpp server.cpp
OBJECTS=$(SOURCES:.cpp=.o)
CLIENT=client
SERVER=server
LIB=libenvcry.so
OBJECTSCRYLIB=Envelope.o Signature.o CryptoStructures.o KeyManager.o

all: $(SOURCES) $(LIB) $(CLIENT) $(SERVER)

$(LIB): $(OBJECTSCRYLIB)
	$(CC) -shared $(OBJECTSCRYLIB) -o $@
	
$(CLIENT): $(OBJECTS)
	$(CC) client.o $(LDFLAGS) -o $@

$(SERVER): $(OBJECTS)
	$(CC) server.o $(LDFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm -rf *o

