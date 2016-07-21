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
        int arg4 = std::atoi(argv[4]);

        if (arg3 < 0 || arg3 > 2) {
            std::cerr << "0, 1 or 2 are the keys available" << std::endl;
            return 1;
        }

        crypto.setPrivateKey(privFile[arg3]);
        crypto.setPublicKey(pubFile[arg3]);

        int toSendSize = arg4;
        srand(time(0));
        std::string randStr;

        for(unsigned int i = 0; i < toSendSize; ++i) {
            randStr += genRandom();
        }

        std::cout << "Message Size: " << toSendSize << " bytes" << std::endl;
        //std::cout << randStr << std::endl;
        for (int q = 0; q < arg2; q++) {

            Data aToSend(toSendSize);
            memcpy(aToSend.data, randStr.c_str(), toSendSize);

            AESData aAESData;
            Data aEncryptedData;
            Data aSignatureData;

            crypto.sendEnvelope(aAESData, aToSend, aEncryptedData, aSignatureData);

            boost::asio::io_service io_service;

            tcp::resolver resolver(io_service);
            tcp::resolver::query query(argv[1], "1300");
            tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

            tcp::socket socket(io_service);
            boost::asio::connect(socket, endpoint_iterator);

            boost::array<char, 128> buf;
            boost::system::error_code error;

            char lengthM[8];

            std::sprintf(lengthM, "%8d", static_cast<int>(arg3));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*8));

            std::sprintf(lengthM, "%8d", static_cast<int>(aAESData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*8));
            socket.write_some(boost::asio::buffer(aAESData.key, aAESData.length));

            socket.write_some(boost::asio::buffer(aAESData.initVector, EVP_MAX_IV_LENGTH));

            std::sprintf(lengthM, "%8d", static_cast<int>(aEncryptedData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*8));
            socket.write_some(boost::asio::buffer(aEncryptedData.data, aEncryptedData.length));

            std::sprintf(lengthM, "%8d", static_cast<int>(aSignatureData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*8));
            socket.write_some(boost::asio::buffer(aSignatureData.data, aSignatureData.length));

            size_t len = socket.read_some(boost::asio::buffer(buf), error);

            if (error == boost::asio::error::eof)
                return 1;
            else if (error)
                throw boost::system::system_error(error);

            socket.close();

        }
        crypto.printAverage();
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
