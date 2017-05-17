#include <ctime>
#include <iostream>
#include <signal.h>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include "Envelope.h"

using boost::asio::ip::tcp;
using namespace CryptoUtils;

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
            Envelope envelope;
            boost::array<char, 9> buf;
            boost::system::error_code ignored_error;

            //Getting the total number of messages the client wants to send
            boost::asio::read(socket_, boost::asio::buffer(buf, 9), ignored_error);
            int numOfMessagesInSession = std::atoi(buf.data());

            //Getting the keypair used, the AES encrypted data, the encrypted data, signature data, decrypt and verify and finally send the cleartext data to the client for verification
            for (int t = 0; t < numOfMessagesInSession; ++t) {

                //Getting the cryptoMsg itself
                boost::asio::read(socket_, boost::asio::buffer(buf, 9), ignored_error);
                int size = std::atoi(buf.data());
                unsigned char* tempCryMsgBuf = new unsigned char[size];
                boost::asio::read(socket_, boost::asio::buffer(tempCryMsgBuf, size), ignored_error);

                std::string receivedMsgEncrypted((char*) tempCryMsgBuf, size);

                delete[] tempCryMsgBuf;

                //Decrypting data
                PlaintextDataReceived aDataReceived;
                std::string strDataReceived = envelope.receiveEnvelope(receivedMsgEncrypted);
                aDataReceived.ParseFromString(strDataReceived);

                //Sending decrypted data in cleartext for verification (this is a PoC)
                char lengthM[9];
                std::sprintf(lengthM, "%8d", strDataReceived.size());
                boost::asio::write(socket_, boost::asio::buffer(lengthM, 9), ignored_error);
                boost::asio::write(socket_, boost::asio::buffer(strDataReceived.data(), strDataReceived.size()), ignored_error);
            }
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
    GOOGLE_PROTOBUF_VERIFY_VERSION;

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
