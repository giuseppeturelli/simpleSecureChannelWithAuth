#include <ctime>
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include "Crypto.h"

using boost::asio::ip::tcp;

std::string make_daytime_string() {
    std::time_t now = std::time(0);
    return std::ctime(&now);
}

int main() {
    try {
        boost::asio::io_service io_service;

        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 1300));

        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;

        privateKey = getPrivateKey();
        publicKey = getPublicKey();
        while (true) {
            tcp::socket socket(io_service);
            acceptor.accept(socket);

            std::string message = make_daytime_string();
            boost::array<char, 4> buf;
            boost::system::error_code error;

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
            serverReceiveEnvelope(publicKey, privateKey, aAESData, aSignatureData, aEncryptedData, aDecryptedData);

            std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
            std::cout << "This after decryption: " << decryptedDataStr << std::endl;



            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(message), ignored_error);
    }

    EVP_PKEY_free(publicKey);
    EVP_PKEY_free(privateKey);

    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


    return 0;
}
