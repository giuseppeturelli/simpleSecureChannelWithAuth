#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include "Crypto.h"

using boost::asio::ip::tcp;

int main(int argc, char* argv[]) {
    std::string toEncrypt = "u8bZgY4IB0CHtAxNTLpa8oCWji8kvAqFx07Mb3sptkBC9RPS3kOe3w4xVFvv77Go01LG2yXzk300yTTJxNNRzv5BDt2LeWcbqhKgIJli1gjlpgy2yeueLaTrkOBMPKIWq1GNyv3E3k5u8kkQUzDumrUUvu6XZvBstOlWKcni2k3lHD382yaDhwvvPau8Acz7Uucaeg1hTr3G0VB2ESSVssAwzbGgS5OUfA24U2ifSOe4IncxWB8WJF9NXbytoM7gSbF2M20iPRUhtqnTDi4oQxDEUUiySCjKRh2kUNQ6Qv4tAfiMbtei6fOrxF6Ivb6oCCY0E2m2OuIOTPVrvVt0s8x2u6oiElyIwjG7oa70TvLEaFRs6rRRNznHf7WyvTeCn0xCPQwYCWXHzaAnDbNIoQv6XlWkNwry1AZRkESvXg8zqkmCYgY8STBZC1nk5El8yGCFUvSnUM4tDgMUh0cUQDiwcRjzHM5b4ZnvTLcLrZ5g5J8PrHe4zPxquj0BCHD3ghUb0oxSqLALTI0qmfGtXuQ9yiAVL8Pq4lY7aSlvfcP2z5V9xTPOsgb5p6hNEGrj8BfswkXrva5pZ6YmD0nvv6GJhDLC0lbW20XWmVr9RR1XkHXUTmZx7DGvrKoG8SOJnKuYWEoHstqNr11LvowKPuKNEzKN4Octy8kH9yFu3Y007qz5cINSXuJajuuUHcVnK1z45cUikeSwbffBVr2tugmEsMbgZKuNTMgzpu2juK0AQ7Y0N4CNgaXTv96vR0Kr2iBeMGnGlBQ8tSjf6cizPbGQrLkRs96VR8Xp6r3b0i08ywapEAPv38eQHWvu093JZcUTpmp13VzeJK9mvphaYWQmaFJU9i8qkRrI5crFItCh0Z4BSEkvlJwwFMhtQv78AzDjWzfbxDaVS1XSk2p5REDS3PmGx9vQts7W90rJuSxsEiLbNS4hNjKx1YeuvCinoTkhwcAEqx4gpBJT7ucRaNHooOK7eEPM03WzSUne2efWfK6MQrNhXD78N9elDYww";

    CryptoCollection crypto;
    try {
        if (argc != 4) {
            std::cerr << "Usage: client <host> #OfRepetitions SelectedKey" << std::endl;
            return 1;
        }

        int arg2 = std::atoi(argv[2]);
        int arg3 = std::atoi(argv[3]);

        if (arg3 < 0 || arg3 > 2) {
            std::cerr << "0, 1 or 2 are the keys available" << std::endl;
            return 1;
        }

        crypto.setPrivateKey(privFile[arg3]);
        crypto.setPublicKey(pubFile[arg3]);

        std::cout << "Message Size: " << toEncrypt.length() << " bytes" << std::endl;// << "Message Content: " <<  toEncrypt << std::endl;
        for (int q = 0; q < arg2; q++) {
            Data aToSend;
            memcpy(aToSend.data, toEncrypt.c_str(), toEncrypt.length());
            aToSend.length = toEncrypt.length();

            AESData aAESData;
            Data aSignatureData;
            Data aEncryptedData;


            crypto.sendEnvelope(aAESData, aToSend, aEncryptedData, aSignatureData);

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
