all:
	g++ client.cpp -lboost_system -lpthread -o client
	g++ server.cpp -lboost_system -lpthread -o server
	g++ helperCryptoFunc.cpp -lcrypto --std=c++11

