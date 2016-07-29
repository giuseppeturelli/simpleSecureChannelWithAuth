#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <boost/shared_ptr.hpp>
#include <map>

static const int keyLength = 1024;

static const std::vector<std::string> privFile = {"./rsaKey1024", "./rsaKey2048", "./rsaKey4096"};
static const std::vector<std::string> pubFile = {"./rsaKey1024_pub", "./rsaKey2048_pub", "./rsaKey4096_pub"};

class Data {
    public:
        Data() : length(0) {}
        Data(int size);
        
        unsigned char* dataPtr();
        const unsigned char* dataPtr() const;
        void resize(int size);
        int size();

        int length;

    private:
        std::vector<unsigned char> data_;
};

class AESData {
    public:
        unsigned char* key;
        unsigned char initVector[EVP_MAX_IV_LENGTH];
        int length;

        AESData() : key(NULL), length(0) {}
        AESData(int size);
        ~AESData();
};

class CryptoCollection {
    public:
        CryptoCollection();
        ~CryptoCollection();

        void printAverage();

        void setPrivateKey(const std::string& keyFilePath);
        void setPublicKey(const std::string& keyFilePath);

        void encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData);
        void decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData);

        void sign(const Data& toSign, Data& oSignatureData);
        bool verify(const Data& signedData, const Data& signatureData);

        void encryptRSA(const Data& toEncrypt, Data& oEncryptedData);
        void decryptRSA(const Data& toDecrypt, Data& oDecryptedData);

        void sendHomeMade(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);
        void receiveHomeMade(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);

        void sendEnvelope(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);
        void receiveEnvelope(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);
        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);
    private:
        void errorHandle();

        void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData);
        void envelope_open(const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData);
        void loadKeys();
        void unloadKeys();
        void loadPrivKey(std::string keyFilePath);
        void loadPubKey(std::string keyFilePath);

        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
        std::vector<float> signTime, encryptTime, decryptTime, verifyTime;
        int messagesReceived = 0;
        std::map<std::string, EVP_PKEY*> keys;
};
