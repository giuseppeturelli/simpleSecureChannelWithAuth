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

void sigIntHandlerFunction(int s) {
    exit(0);
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
            CryptoCollection crypto;
            boost::array<char, 8> buf;
            boost::system::error_code ignored_error;

            boost::asio::read(socket_, boost::asio::buffer(buf, 8), ignored_error);
            int numOfMessagesInSession = std::atoi(buf.data());

            for (int t = 0; t < numOfMessagesInSession; ++t) {

                boost::asio::read(socket_, boost::asio::buffer(buf, 8), ignored_error);
                int keyUsed = std::atoi(buf.data());

                crypto.setPrivateKey(privFile[keyUsed]);
                crypto.setPublicKey(pubFile[keyUsed]);

                boost::asio::read(socket_, boost::asio::buffer(buf, 8), ignored_error);
                int length = std::atoi(buf.data());
                AESData aAESData(length);
                boost::asio::read(socket_, boost::asio::buffer(aAESData.key, aAESData.length), ignored_error);
                boost::asio::read(socket_, boost::asio::buffer(aAESData.initVector,  EVP_MAX_IV_LENGTH), ignored_error);

                boost::asio::read(socket_, boost::asio::buffer(buf, 8), ignored_error);
                length = std::atoi(buf.data());
                Data aEncryptedData(length);
                boost::asio::read(socket_, boost::asio::buffer(aEncryptedData.dataPtr(), aEncryptedData.length), ignored_error);

                boost::asio::read(socket_, boost::asio::buffer(buf, 8), ignored_error);
                length = std::atoi(buf.data());
                Data aSignatureData(length);
                boost::asio::read(socket_, boost::asio::buffer(aSignatureData.dataPtr(), aSignatureData.length), ignored_error);

                Data aDecryptedData;
                crypto.receiveEnvelope(aAESData, aSignatureData, aEncryptedData, aDecryptedData);

                int le = aDecryptedData.length;

                char lengthM[8];
                std::sprintf(lengthM, "%8d", aDecryptedData.length);
                aDecryptedData.length = le;
                boost::asio::write(socket_, boost::asio::buffer(lengthM, 8), ignored_error);
                boost::asio::write(socket_, boost::asio::buffer(aDecryptedData.dataPtr(), aDecryptedData.length), ignored_error);


                //char* data = (char*) malloc(aDecryptedData.length + 1);
                //data[aDecryptedData.length] = '\0';
                //memcpy(data, aDecryptedData.dataPtr(), aDecryptedData.length);
                //std::string strin(data);
                //std::cout << "STRR: " << strin << std::endl;
            }

            crypto.printAverage();
        }

        private:
            tcp_connection(boost::asio::io_service& io_service) : socket_ (io_service) {}
            void handle_write(const boost::system::error_code&, size_t) {}
            tcp::socket socket_;
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
            start_accept();
            if (!error) {
                new_connection->start();
            }
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
    tcp_server server(io_service);
    io_service.run();

    return 0;
}
