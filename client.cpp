#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Envelope.h"

using boost::asio::ip::tcp;
using namespace CryptoUtils;

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char genRandom() {
    return alphanum[rand() % (sizeof(alphanum) -1)];
}

int main(int argc, char* argv[]) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    Envelope envelope;

    try {
        if (argc != 4) {
            std::cerr << "Usage: client <host> #OfRepetitions #OfBytes" << std::endl;
            return 1;
        }

        int arg2 = std::atoi(argv[2]);
        unsigned int arg3 = std::atoi(argv[3]);

        unsigned int toSendSize = arg3;

        //Socket conneciton
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(argv[1], "1300");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        std::cout << "Message Size: " << toSendSize << " bytes" << std::endl;
        //std::cout << randStr << std::endl;

        boost::array<char, 9> buf;
        boost::system::error_code ignored_error;

        //Informing server of the total number of messages
        char lengthM[9];
        std::sprintf(lengthM, "%8d", static_cast<int>(arg2));
        boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);

        //Generating a random string of the desired size
        PlaintextDataToSend aToSend;
        aToSend.add_receiverid("nox.amadeus.net");
        srand(time(0));
        for(unsigned int i = 0; i < toSendSize; ++i) {
            aToSend.mutable_data()->append(1, genRandom());
        }

        //Encrypting, sending the encrypted data, receiving the decrypted data (in clear, this is a PoC) and verifying that the cleartext data matches
        for (int q = 0; q < arg2; q++) {
            std::string aToSendStr;
            aToSend.SerializeToString(&aToSendStr);
            std::string cryptoMsg = envelope.sendEnvelope(aToSendStr);

            //Sending the cryptoMsg itslef
            std::sprintf(lengthM, "%8d", static_cast<int>(cryptoMsg.size()));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(cryptoMsg.data(), cryptoMsg.size()), ignored_error);

            //Getting the data previously sent in cleartext from the server
            boost::asio::read(socket, boost::asio::buffer(buf, 9), ignored_error);
            int size = std::atoi(buf.data());
            unsigned char* tempReceivedData = new unsigned char[size];
            boost::asio::read(socket, boost::asio::buffer(tempReceivedData, size), ignored_error);

            std::string strDataFromServer((char*)tempReceivedData, size);

            delete[] tempReceivedData;

            PlaintextDataReceived dataFromServer;
            dataFromServer.ParseFromString(strDataFromServer);
            //Checking for equality
            if (dataFromServer.data().compare(aToSend.data()))
                std::cout << "Strings *DO NOT* compare EQUAL, test failed!" << std::endl;
        }
        socket.close();
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
