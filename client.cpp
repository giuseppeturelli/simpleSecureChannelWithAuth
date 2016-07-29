#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"

using boost::asio::ip::tcp;

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char genRandom() {
    return alphanum[rand() % (sizeof(alphanum) -1)];
}

int main(int argc, char* argv[]) {

    CryptoCollection crypto;
    try {
        if (argc != 5) {
            std::cerr << "Usage: client <host> #OfRepetitions SelectedKey #OfBytes" << std::endl;
            return 1;
        }

        int arg2 = std::atoi(argv[2]);
        int arg3 = std::atoi(argv[3]);
        unsigned int arg4 = std::atoi(argv[4]);

        if (arg3 < 0 || arg3 > 2) {
            std::cerr << "0, 1 or 2 are the keys available" << std::endl;
            return 1;
        }

        crypto.setPrivateKey(privFile[arg3]);
        crypto.setPublicKey(pubFile[arg3]);

        unsigned int toSendSize = arg4;
        std::string randStr;
        Data aToSend(toSendSize);

        //Socket conneciton
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(argv[1], "1300");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        std::cout << "Message Size: " << toSendSize << " bytes" << std::endl;
        //std::cout << randStr << std::endl;

        boost::array<char, 8> buf;
        boost::system::error_code ignored_error;

        char lengthM[8];

        std::sprintf(lengthM, "%8d", static_cast<int>(arg2));
        boost::asio::write(socket, boost::asio::buffer(lengthM, 8), ignored_error);


        for (int q = 0; q < arg2; q++) {

            randStr.clear();
            srand(time(0));
            for(unsigned int i = 0; i < toSendSize; ++i) {
                randStr += genRandom();
            }

            memcpy(aToSend.dataPtr(), randStr.c_str(), toSendSize);

            AESData aAESData;
            Data aEncryptedData;
            Data aSignatureData;

            crypto.sendEnvelope(aAESData, aToSend, aEncryptedData, aSignatureData);

            std::sprintf(lengthM, "%8d", static_cast<int>(arg3));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 8), ignored_error);

            std::sprintf(lengthM, "%8d", static_cast<int>(aAESData.length));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 8), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aAESData.key, aAESData.length), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aAESData.initVector, EVP_MAX_IV_LENGTH), ignored_error);

            std::sprintf(lengthM, "%8d", static_cast<int>(aEncryptedData.length));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 8), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aEncryptedData.dataPtr(), aEncryptedData.length), ignored_error);

            std::sprintf(lengthM, "%8d", static_cast<int>(aSignatureData.length));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 8), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aSignatureData.dataPtr(), aSignatureData.length), ignored_error);

            boost::asio::read(socket, boost::asio::buffer(buf, 8), ignored_error);
            int length = std::atoi(buf.data());
            Data dataFromServer(length);
            boost::asio::read(socket, boost::asio::buffer(dataFromServer.dataPtr(), dataFromServer.length), ignored_error);

            char* dataFromSrvChar = (char*) malloc(dataFromServer.length + 1); 
            dataFromSrvChar[dataFromServer.length] = '\0';
            memcpy(dataFromSrvChar, dataFromServer.dataPtr(), dataFromServer.length);
            std::string stringFromSrv(dataFromSrvChar);
            if (stringFromSrv.compare(randStr) != 0)
                std::cout << "Strings *DO NOT* compare EQUAL, test failed!" << std::endl;

            free(dataFromSrvChar);

        }
        crypto.printAverage();
        socket.close();
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
