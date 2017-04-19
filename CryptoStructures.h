#ifndef CRYPTO_STRUCTURES_H
#define CRYPTO_STRUCTURES_H

#include <vector>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <exception>

namespace CryptoUtils {

class Data {
    private:
        std::vector<unsigned char> data_;
    public:
        Data();
        Data(int size);

        unsigned char* dataPtr();
        const unsigned char* dataPtr() const;
        void resize(int size);
        int size();
        const int size() const;
        bool equal(const Data& toCompare);

};

class EncryptedData {
    public:
        Data encryptedData;
        Data initVector;
};

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
