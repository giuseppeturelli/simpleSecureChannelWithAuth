all:
	g++ -g client.cpp Crypto.cpp -lboost_system -lpthread -lcrypto -o client --std=c++11
	g++ -g server.cpp Crypto.cpp -lboost_system -lpthread -lcrypto -o server --std=c++11

