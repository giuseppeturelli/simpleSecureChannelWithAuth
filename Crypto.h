#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <vector>
#include <numeric>
#include <boost/shared_ptr.hpp>

static const int keyLength = 1024;


static const std::vector<std::string> privFile = {"./rsaKey1024", "./rsaKey2048", "./rsaKey4096" };
static const std::vector<std::string> pubFile = {"./rsaKey1024_pub", "./rsaKey2048_pub", "./rsaKey4096_pub"};

class Data {
    public:
        unsigned char* data;
        long unsigned int length;

        Data() : data(NULL), length(0) {}

        Data(int size) {
            data = (unsigned char*) malloc(size*sizeof(unsigned char));
            memset(data, 0, size);
            length = size;
        }

        ~Data() {
            free(data);
        }
};

class AESData {
    public:
        unsigned char* key;
        unsigned char initVector[EVP_MAX_IV_LENGTH];
        int length = 0;

        AESData() {
            key = (unsigned char*) malloc(keyLength*sizeof(unsigned char));
            memset(key, 0, keyLength);
            //length = bufferLength;
        }

        AESData(int size) {
            key = (unsigned char*) malloc(size*sizeof(unsigned char));
            memset(key, 0, size);
            length = size;
        }

        ~AESData() {
            free(key);
        }
};

//Helper Functions
void printAverage();
//Getting RSA keypair


class CryptoCollection {
    public:
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

        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
        std::vector<float> signTime, encryptTime, decryptTime, verifyTime;
        int messagesReceived = 0;
};
