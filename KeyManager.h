#include "BaseSixtyFour.h"
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

static const std::vector<std::string> privFile = {"./cryptoFiles/rsaKey1024", "./cryptoFiles/rsaKey2048", "./cryptoFiles/rsaKey4096"};
static const std::vector<std::string> pubFile = {"./cryptoFiles/rsaKey1024_pub", "./cryptoFiles/rsaKey2048_pub", "./cryptoFiles/rsaKey4096_pub"};
static const std::string aesFile("./cryptoFiles/tempaesKey256");

class KeyManager {
    public:
        KeyManager();
        virtual ~KeyManager();

        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);

        virtual EVP_PKEY* getThePrivateKey();
        virtual EVP_PKEY* getPublicKeyFor(const std::string& keyName);

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
