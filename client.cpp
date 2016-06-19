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

        std::string toEncrypt = "AllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainx";
        //Getting RSA Private key
        FILE* fp;
        EVP_PKEY* privateKey;

        if ((fp = fopen("/etc/ssh/ssh_host_rsa_key", "r")) != NULL) {
            privateKey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
            if (privateKey == NULL)
                errorHandle();
            std::cout << "Loaded Private RSA key!" << std::endl;
            fclose(fp);
        } else {
            std::cout << "Private RSA key missing, exiting!" << std::endl;
        }
        //Getting RSA Public key
        EVP_PKEY* publicKey;

        if ((fp = fopen("/etc/ssh/ssh_host_rsa_key_pub", "r")) != NULL) {
            publicKey = PEM_read_PUBKEY(fp, NULL, 0, NULL);
            if (publicKey == NULL)
                errorHandle();

            std::cout << "Loaded Public RSA key!" << std::endl;
            fclose(fp);
        } else {
            std::cout << "Public RSA key missing, exiting!" << std::endl;
            exit(1);
        }

        Data aToSend;
        memcpy(aToSend.data, toEncrypt.c_str(), toEncrypt.length());
        aToSend.length = toEncrypt.length();

        AESData aAESData;
        Data aSignatureData;
        Data aEncryptedData;

        std::cout << "------------------Client preparing Data To send Envelope------------------" << std::endl;
        clientSendEnvelope(publicKey, privateKey, aAESData, aToSend, aEncryptedData, aSignatureData);


        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(argv[1], "1300");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        while (true) {
            boost::array<char, 128> buf;
            boost::system::error_code error;

            size_t lent = socket.write_some(boost::asio::buffer(aAESData.key));
            std::cout << "Key client side: " << std::hex << aAESData.key << std::endl;

            size_t len = socket.read_some(boost::asio::buffer(buf), error);

            if (error == boost::asio::error::eof)
                break;
            else if (error)
                throw boost::system::system_error(error);

            std::cout.write(buf.data(), len);
        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    
    return 0;
}
