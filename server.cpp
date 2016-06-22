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

        EVP_PKEY* privateKey[3];
        EVP_PKEY* publicKey[3];

        for (int i = 0; i < 3; i++) {
            privateKey[i] = getPrivateKey(privFile[i]);
            publicKey[i] = getPublicKey(pubFile[i]);
        }

        while (true) {
            tcp::socket socket(io_service);
            acceptor.accept(socket);

            std::cout << std::endl <<  "---------------------------New Message Received---------------------------" << std::endl;
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
            serverReceiveEnvelope(publicKey[keyUsed], privateKey[keyUsed], aAESData, aSignatureData, aEncryptedData, aDecryptedData);

            std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
            std::cout << "Decrypted Message Size: " << decryptedDataStr.length() << std::endl << "Decrypted Message Content: " <<  decryptedDataStr << std::endl;



            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(message), ignored_error);
    }

    //Never reached for the moment
    for (int i = 0; i < 3; i++) {
        EVP_PKEY_free(publicKey[i]);
        EVP_PKEY_free(privateKey[i]);
        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


    return 0;
}
