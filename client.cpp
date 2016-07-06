#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"

using boost::asio::ip::tcp;

int main(int argc, char* argv[]) {
    CryptoCollection crypto;
    try {
        if (argc != 4) {
            std::cerr << "Usage: client <host> #OfRepetitions SelectedKey" << std::endl;
            return 1;
        }
        EVP_PKEY* privateKey[3];
        EVP_PKEY* publicKey[3];

        for (int i = 0; i < 3; i++) {
            privateKey[i] = crypto.getPrivateKey(privFile[i]);
            publicKey[i] = crypto.getPublicKey(pubFile[i]);
        }
        int arg2 = std::atoi(argv[2]);
        int arg3 = std::atoi(argv[3]);

        if (arg3 < 0 || arg3 > 2) {
            std::cerr << "0, 1 or 2 are the keys available" << std::endl;
            return 1;
        }

        std::cout << "Message Size: " << toEncrypt.length() << std::endl;// << "Message Content: " <<  toEncrypt << std::endl;
        for (int q = 0; q < arg2; q++) {
            Data aToSend;
            memcpy(aToSend.data, toEncrypt.c_str(), toEncrypt.length());
            aToSend.length = toEncrypt.length();

            AESData aAESData;
            Data aSignatureData;
            Data aEncryptedData;


            crypto.clientSendEnvelope(publicKey[arg3], privateKey[arg3], aAESData, aToSend, aEncryptedData, aSignatureData);

            boost::asio::io_service io_service;

            tcp::resolver resolver(io_service);
            tcp::resolver::query query(argv[1], "1300");
            tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

            tcp::socket socket(io_service);
            boost::asio::connect(socket, endpoint_iterator);

            boost::array<char, 128> buf;
            boost::system::error_code error;

            char lengthM[4];

            std::sprintf(lengthM, "%4d", static_cast<int>(arg3));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));

            std::sprintf(lengthM, "%4d", static_cast<int>(aAESData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
            socket.write_some(boost::asio::buffer(aAESData.key, aAESData.length));

            socket.write_some(boost::asio::buffer(aAESData.initVector, bufferLength));

            std::sprintf(lengthM, "%4d", static_cast<int>(aEncryptedData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
            socket.write_some(boost::asio::buffer(aEncryptedData.data, aEncryptedData.length));

            std::sprintf(lengthM, "%4d", static_cast<int>(aSignatureData.length));
            socket.write_some(boost::asio::buffer(lengthM, sizeof(char)*4));
            socket.write_some(boost::asio::buffer(aSignatureData.data, aSignatureData.length));

            size_t len = socket.read_some(boost::asio::buffer(buf), error);

            //std::cout.write(buf.data(), len);

            if (error == boost::asio::error::eof)
                return 1;
            else if (error)
                throw boost::system::system_error(error);

        }
        printAverage();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    
    return 0;
}
