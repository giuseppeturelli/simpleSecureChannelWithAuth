CC=g++
CFLAGS=-std=c++11 -Wall -g
LDFLAGS= -lcrypto -lboost_system -lpthread
SOURCES=Envelope.cpp Signature.cpp CryptoStructures.cpp KeyManager.cpp 
SOURCESCLIENT=$(SOURCES) client.cpp
SOURCESSERVER=$(SOURCES) server.cpp
OBJECTSSERVER=$(SOURCESSERVER:.cpp=.o)
OBJECTSCLIENT=$(SOURCESCLIENT:.cpp=.o)
CLIENTEX=client
SERVEREX=server

all: $(SOURCESCLIENT) $(SURCESSERVER) $(CLIENTEX) $(SERVEREX)
	
$(CLIENTEX): $(OBJECTSCLIENT)
	$(CC) $(LDFLAGS) $(OBJECTSCLIENT) -o $@

$(SERVEREX): $(OBJECTSSERVER)
	$(CC) $(LDFLAGS) $(OBJECTSSERVER) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm -rf *o

