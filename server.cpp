#include <ctime>
#include <iostream>
#include <string>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <iostream>

using boost::asio::ip::tcp;

std::string make_daytime_string() {
    std::time_t now = std::time(0);
    return std::ctime(&now);
}

int main() {
    try {
        boost::asio::io_service io_service;

        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 1300));

        while (true) {
            tcp::socket socket(io_service);
            acceptor.accept(socket);

            std::string message = make_daytime_string();
            boost::array<char, 1024> buf;
            boost::system::error_code error;
            size_t len = socket.read_some(boost::asio::buffer(buf), error);
            std::string dataStr(buf.begin(), buf.end());
            std::cout << "Sever Side: " << std::hex << dataStr << std::endl;

            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(message), ignored_error);
        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
