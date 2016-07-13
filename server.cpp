#include <ctime>
#include <iostream>
#include <signal.h>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include "Crypto.h"

using boost::asio::ip::tcp;

void sigIntHandlerFunction(int s) {
    printAverage();
    exit(0);
}

std::string make_daytime_string() {
    std::time_t now = std::time(0);
    return std::ctime(&now);
}

int main() {

    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = sigIntHandlerFunction;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    CryptoCollection crypto;
    try {
        boost::asio::io_service io_service;

        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 1300));

        while (true) {
            tcp::socket socket(io_service);
            acceptor.accept(socket);

            //std::cout << std::endl <<  "---------------------------New Message Received---------------------------" << std::endl;
            std::string message = make_daytime_string();
            boost::array<char, 4> buf;
            boost::system::error_code error;

            socket.read_some(boost::asio::buffer(buf, sizeof(char)*4), error);
            int keyUsed = std::atoi(buf.data());

            AESData aAESData;
            socket.read_some(boost::asio::buffer(buf, sizeof(char)*4), error);
            aAESData.length = std::atoi(buf.data());
            socket.read_some(boost::asio::buffer(aAESData.key, aAESData.length), error);
            socket.read_some(boost::asio::buffer(aAESData.initVector, bufferLength), error);

            Data aEncryptedData;
            socket.read_some(boost::asio::buffer(buf, sizeof(char)*4), error);
            aEncryptedData.length = std::atoi(buf.data());
            socket.read_some(boost::asio::buffer(aEncryptedData.data, aEncryptedData.length), error);

            Data aSignatureData;
            socket.read_some(boost::asio::buffer(buf, sizeof(char)*4), error);
            aSignatureData.length = std::atoi(buf.data());
            socket.read_some(boost::asio::buffer(aSignatureData.data, aSignatureData.length), error);

            Data aDecryptedData;
            crypto.setPrivateKey(privFile[keyUsed]);
            crypto.setPublicKey(pubFile[keyUsed]);
            crypto.receiveEnvelope(aAESData, aSignatureData, aEncryptedData, aDecryptedData);

            std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
            //std::cout << "Decrypted Message Size: " << decryptedDataStr.length() << std::endl << "Decrypted Message Content: " <<  decryptedDataStr << std::endl;

            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(message), ignored_error);
        }
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
