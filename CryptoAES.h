#include "BaseSixtyFour.h"
#include <openssl/evp.h>
#include <cstring>
#include <vector>

namespace CryptoUtils {

static const int AESkeyLength = 32;

static const std::string aesFile("./cryptoFiles/tempaesKey256");

class Data {
    public:
        Data() {}
        Data(int size);

        unsigned char* dataPtr();
        const unsigned char* dataPtr() const;
        void resize(int size);
        int size();
        const int size() const;
        bool equal(const Data& toCompare);

    private:
        std::vector<unsigned char> data_;
};

class EncryptedData {
    public:
        Data encryptedData;
        Data initVector;
};

class CryptoAES {
    public:
        CryptoAES();
        virtual ~CryptoAES();

        void loadAESKey(std::string keyFilePath);
        void generateAndStoreAESKey(std::string keyFilePath);
        std::string encryptAESString(const std::string& stringToEncrypt);
        std::string decryptAESString(const std::string& base64StringToDecrypt);
    private:
        void errorHandle();
        BaseSixtyFour aB64;
        Data theAESKey;
        void encryptAES(const Data& iAESData, const Data& toEncrypt, EncryptedData& oEncryptedData);
        void decryptAES(const Data& iAESData, const EncryptedData& toDecrypt, Data& oDecryptedData);
        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);
};
}//namespace CryptoUtils
