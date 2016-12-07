#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"

using boost::asio::ip::tcp;
using namespace CryptoUtils;

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char genRandom() {
    return alphanum[rand() % (sizeof(alphanum) -1)];
}

int main(int argc, char* argv[]) {

    CryptoCollection crypto;
    std::string toE("All these moments will be lost in time like tears in rain");
    std::string encrStr = crypto.encryptAESString(toE);
    std::cout << "EncrSTR: " << encrStr << std::endl;

    std::string decrStr = crypto.decryptAESString(encrStr);
    std::cout << "EncrSTR: " << decrStr << std::endl;

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
        Data aToSend(toSendSize);
        srand(time(0));
        unsigned char* innerVectorPtr = aToSend.dataPtr();
        for(int i = 0; i < aToSend.size(); ++i) {
            innerVectorPtr[i] = genRandom();
        }

        //Encrypting, sending the encrypted data, receiving the decrypted data (in clear, this is a PoC) and verifying that the cleartext data matches
        for (int q = 0; q < arg2; q++) {
            Data aAESData;
            EncryptedData aEncryptedData;
            Data aSignatureData;

            crypto.sendEnvelope(aAESData, aToSend, aEncryptedData, aSignatureData);

            //Sending info about the private keypair used
            std::sprintf(lengthM, "%8d", static_cast<int>(arg3));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);

            //Sending the AES encrypted key
            std::sprintf(lengthM, "%8d", static_cast<int>(aAESData.size()));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aAESData.dataPtr(), aAESData.size()), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aEncryptedData.initVector.dataPtr(), aEncryptedData.initVector.size()), ignored_error);

            //Sending encrypted data
            std::sprintf(lengthM, "%8d", static_cast<int>(aEncryptedData.encryptedData.size()));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aEncryptedData.encryptedData.dataPtr(), aEncryptedData.encryptedData.size()), ignored_error);

            //Sending signature data
            std::sprintf(lengthM, "%8d", static_cast<int>(aSignatureData.size()));
            boost::asio::write(socket, boost::asio::buffer(lengthM, 9), ignored_error);
            boost::asio::write(socket, boost::asio::buffer(aSignatureData.dataPtr(), aSignatureData.size()), ignored_error);

            //Getting the data previously sent in cleartext from the server
            boost::asio::read(socket, boost::asio::buffer(buf, 9), ignored_error);
            int length = std::atoi(buf.data());
            Data dataFromServer(length);
            boost::asio::read(socket, boost::asio::buffer(dataFromServer.dataPtr(), dataFromServer.size()), ignored_error);

            //Checking for equality
            if (!dataFromServer.equal(aToSend))
                std::cout << "Strings *DO NOT* compare EQUAL, test failed!" << std::endl;
        }
        crypto.printAverage();
        socket.close();
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
