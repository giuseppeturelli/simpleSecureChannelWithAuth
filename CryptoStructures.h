#ifndef CRYPTO_STRUCTURES_H
#define CRYPTO_STRUCTURES_H

#include <vector>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <exception>
#include "secureChannel.pb.h"
#include "pubSecureChannel.pb.h"

namespace CryptoUtils {

class CryptoException: public std::exception {
    public:
        CryptoException(const std::string& message);

        virtual const char* what() const throw();

    protected:
        std::string _msg;
};

void errorHandle();
}//namespace CryptoUtils
#endif //CRYPTO_STRUCTURES_H
