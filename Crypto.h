#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>
#include <vector>
#include <numeric>

static const int bufferLength = 2048;
static const int keyLength = 1024;

static std::vector<float> signTime, encryptTime, decryptTime, verifyTime;
static int messagesReceived = 0;

static const std::vector<std::string> privFile = {"./rsaKey1024", "./rsaKey2048", "./rsaKey4096" };
static const std::vector<std::string> pubFile = {"./rsaKey1024_pub", "./rsaKey2048_pub", "./rsaKey4096_pub"};

struct Data {
    unsigned char data[bufferLength];
    long unsigned int length = 0;
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[EVP_MAX_IV_LENGTH];
    int length = 0;
};

//Helper Functions
void printAverage();
//Getting RSA keypair


class CryptoCollection {
    public:
        ~CryptoCollection();

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
    private:
        void generateRandomBuffer(unsigned char* ioRandBuffer, int size);
        void errorHandle();

        void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData);
        void envelope_open(const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData);

        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
};
