#include <ctime>
#include <iostream>
#include <signal.h>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include "Crypto.h"

using boost::asio::ip::tcp;

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


CryptoCollection crypto;

void sigIntHandlerFunction(int s) {
    crypto.printAverage();
    exit(0);
}

std::string make_daytime_string() {
    std::time_t now = std::time(0);
    return std::ctime(&now);
}

class tcp_connection : public boost::enable_shared_from_this<tcp_connection> {
    public:
        typedef boost::shared_ptr<tcp_connection> pointer;

        static pointer create(boost::asio::io_service& io_service) {
            return pointer(new tcp_connection(io_service));
        }

        tcp::socket& socket() {
            return socket_;
        }

        void start() {
            message_ = "KOOL";

            boost::asio::async_write(socket_, boost::asio::buffer(message_), boost::bind(&tcp_connection::handle_write,
            shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
        }

        private:
            tcp_connection(boost::asio::io_service& io_service) : socket_ (io_service) {}

            void handle_write(const boost::system::error_code&, size_t) {}

            tcp::socket socket_;
            std::string message_;
};


class tcp_server {
    public:
        tcp_server(boost::asio::io_service& io_service) : acceptor_(io_service, tcp::endpoint(tcp::v4(), 1300)) {
            start_accept();
        }

    private:
        void start_accept() {
            tcp_connection::pointer new_connection = tcp_connection::create(acceptor_.get_io_service());

            acceptor_.async_accept(new_connection->socket(), boost::bind(&tcp_server::handle_accept, this,
            new_connection, boost::asio::placeholders::error));
        }

        void handle_accept(tcp_connection::pointer new_connection, const boost::system::error_code& error) {
            if (!error) {
                new_connection->start();
            }

            start_accept();
        }

        tcp::acceptor acceptor_;
};


int main() {

    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = sigIntHandlerFunction;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    //Acceptor creation
    boost::asio::io_service io_service;
    tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 1300));

    try {
        while (true) {

            tcp::socket socket(io_service);
            acceptor.accept(socket);

            boost::array<char, 8> buf;
            boost::system::error_code error;

            size_t len = socket.read_some(boost::asio::buffer(buf, sizeof(char)*8), error);
            int numOfMessagesInSession = std::atoi(buf.data());

            for (int t = 0; t < numOfMessagesInSession; ++t) {

                //std::cout << std::endl <<  "---------------------------New Message Received---------------------------" << std::endl;
                std::string message = make_daytime_string();

                len = socket.read_some(boost::asio::buffer(buf, sizeof(char)*8), error);
                int keyUsed = std::atoi(buf.data());

                crypto.setPrivateKey(privFile[keyUsed]);
                crypto.setPublicKey(pubFile[keyUsed]);

                len = socket.read_some(boost::asio::buffer(buf, sizeof(char)*8), error);
                int length = std::atoi(buf.data());

                AESData aAESData(length);
                len = 0;
                while(len < aAESData.length) {
                    len += socket.read_some(boost::asio::buffer(aAESData.key + len, aAESData.length - len), error);
                }

                len = 0;
                while(len < EVP_MAX_IV_LENGTH) {
                    len += socket.read_some(boost::asio::buffer(aAESData.initVector + len,  EVP_MAX_IV_LENGTH - len), error);
                }

                len = socket.read_some(boost::asio::buffer(buf, sizeof(char)*8), error);
                length = std::atoi(buf.data());

                Data aEncryptedData(length);
                len = 0;
                while(len < aEncryptedData.length) {
                    len += socket.read_some(boost::asio::buffer(aEncryptedData.data + len, aEncryptedData.length - len), error);
                }

                len = socket.read_some(boost::asio::buffer(buf, sizeof(char)*8), error);
                length = std::atoi(buf.data());

                Data aSignatureData(length);
                len = 0;
                while (len < aSignatureData.length) {
                    len += socket.read_some(boost::asio::buffer(aSignatureData.data + len, aSignatureData.length - len), error);
                }

                Data aDecryptedData;
                crypto.receiveEnvelope(aAESData, aSignatureData, aEncryptedData, aDecryptedData);

                char* printData = (char*) malloc(aDecryptedData.length + 1);
                printData[aDecryptedData.length] = '\0';
                memcpy(printData, aDecryptedData.data, aDecryptedData.length);
                //std::cout << "DecryptBufSize: " << aDecryptedData.length << std::endl;
                //printf("%s\n", printData);

                boost::system::error_code ignored_error;
                boost::asio::write(socket, boost::asio::buffer(message), ignored_error);
            }
        }
    }

    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
