#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"

using boost::asio::ip::tcp;

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: client <host>" << std::endl;
            return 1;
        }
        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;


        privateKey = getPrivateKey();
        publicKey = getPublicKey();
        Data aToSend;
        memcpy(aToSend.data, toEncrypt.c_str(), toEncrypt.length());
        aToSend.length = toEncrypt.length();

        AESData aAESData;
        Data aSignatureData;
        Data aEncryptedData;

        std::cout << "Message Size: " << toEncrypt.length() << std::endl << "Message Content: " <<  toEncrypt << std::endl;
        clientSendEnvelope(publicKey, privateKey, aAESData, aToSend, aEncryptedData, aSignatureData);

        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(argv[1], "1300");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        boost::array<char, 128> buf;
        boost::system::error_code error;

        char lengthM[4];


        std::sprintf(lengthM, "%4d", static_cast<int>(aAESData.length));
        size_t len = socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
        len = socket.write_some(boost::asio::buffer(aAESData.key, aAESData.length));

        len = socket.write_some(boost::asio::buffer(aAESData.initVector, bufferLength));

        std::sprintf(lengthM, "%4d", static_cast<int>(aEncryptedData.length));
        len = socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
        len = socket.write_some(boost::asio::buffer(aEncryptedData.data, aEncryptedData.length));

        std::sprintf(lengthM, "%4d", static_cast<int>(aSignatureData.length));
        len = socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
        len = socket.write_some(boost::asio::buffer(aSignatureData.data, aSignatureData.length));

        len = socket.read_some(boost::asio::buffer(buf), error);

        std::cout.write(buf.data(), len);

        if (error == boost::asio::error::eof)
            return 1;
        else if (error)
            throw boost::system::system_error(error);

    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    
    return 0;
}
