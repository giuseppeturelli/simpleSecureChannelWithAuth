#ifndef KEYMANAGER_H
#define KEYMANAGER_H
#include "CryptoStructures.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <boost/shared_ptr.hpp>
#include <map>

namespace CryptoUtils {

static const int AESkeyLength = 32;

static const std::vector<std::string> privFile = {"./cryptoFiles/rsaKey1024", "./cryptoFiles/rsaKey2048", "./cryptoFiles/rsaKey4096", "./cryptoFiles/eccKeyP160"};
static const std::vector<std::string> pubFile = {"./cryptoFiles/rsaKey1024_pub", "./cryptoFiles/rsaKey2048_pub", "./cryptoFiles/rsaKey4096_pub", "./cryptoFiles/eccKeyP160_pub"};
static const std::string aesFile("./cryptoFiles/tempaesKey256");


class KeyManager {
    public:
        KeyManager();
        virtual ~KeyManager();

        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);

        virtual EVP_PKEY* getEncryptionPrivateKey();
        virtual EVP_PKEY* getSignaturePrivateKey();
        virtual EVP_PKEY* getEncryptionPublicKeyFor(const std::string& keyName);
        virtual EVP_PKEY* getSignaturePublicKeyFor(const std::string& keyName);

        virtual std::string getMyID() { return "nox.amadeus.net"; }

    private:
        EVP_PKEY* _myPrivateKey;
        void loadKeys();
        void unloadKeys();
        void loadPrivKey(std::string keyFilePath);
        void loadPubKey(std::string keyFilePath);

        std::map<std::string, EVP_PKEY*> keys;
        static const int numOfAsymmetricKeypairs = 1;
};

}//namespace CryptoUtils
#endif //KEYMANAGER_H
