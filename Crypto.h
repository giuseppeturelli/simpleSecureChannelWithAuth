#include "BaseSixtyFour.h"
#include "Structures.h"
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

class CryptoCollection {
    public:
        CryptoCollection();
        ~CryptoCollection();

        void printAverage();

        void setPrivateKey(const std::string& keyFilePath);
        void setPublicKey(const std::string& keyFilePath);

        void encryptAES(const Data& iAESData, const Data& toEncrypt, EncryptedData& oEncryptedData);
        void decryptAES(const Data& iAESData, const EncryptedData& toDecrypt, Data& oDecryptedData);

        void sign(const EncryptedData& toSign, Data& oSignatureData);
        bool verify(const EncryptedData& signedData, const Data& signatureData);

        void encryptRSA(const Data& toEncrypt, Data& oEncryptedData);
        void decryptRSA(const Data& toDecrypt, Data& oDecryptedData);

        void sendHomeMade(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData);
        void receiveHomeMade(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData);

        void sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData);
        void receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData);
        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);

        void loadAESKey(std::string keyFilePath);
        void generateAndStoreAESKey(std::string keyFilePath);
        std::string encryptAESString(const std::string& stringToEncrypt);
        std::string decryptAESString(const std::string& base64StringToDecrypt);
    private:
        void errorHandle();

        void envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, EncryptedData& oEncryptedData, Data& oAESData);
        void envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData);
        void loadKeys();
        void unloadKeys();
        void loadPrivKey(std::string keyFilePath);
        void loadPubKey(std::string keyFilePath);

        BaseSixtyFour aB64;
        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
        std::vector<float> signTime, encryptTime, decryptTime, verifyTime;
        int messagesReceived = 0;
        std::map<std::string, EVP_PKEY*> keys;
        static const int numOfAsymmetricKeypairs = 1;
        Data theAESKey;
};

}//namespace CryptoUtils
