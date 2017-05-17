#include "CryptoStructures.h"

namespace CryptoUtils {

    CryptoException::CryptoException(const std::string& message): _msg(message) {}

    const char* CryptoException::what() const throw() { return _msg.c_str(); }


    void errorHandle() {
        char error[1024];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), error, 1024);
        CryptoException e(error);
        std::cout << "Error value: " << error << std::endl;
        throw e;
    }

}//namespace CryptoUtils
