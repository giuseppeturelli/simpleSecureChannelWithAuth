#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

static const int bufferLength = 2048;
static const int keyLength = 1024;

struct Data {
    unsigned char data[bufferLength];
    long unsigned int length = 0;

    template <typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & data;
        ar & length;
    }
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[bufferLength];
    int length = 0;

    template <typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & key;
        ar & initVector;
        ar & length;
    }
};

void errorHandle();

void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData);

void envelope_open(EVP_PKEY* privateKey, const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData);

void encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData);

void decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData);

void sign(EVP_PKEY* privateKey, const Data& toSign, Data& oSignatureData);

bool verify(EVP_PKEY* publicKey, const Data& signedData, const Data& signatureData);

void encryptRSA(EVP_PKEY* publicKey, const Data& toEncrypt, Data& oEncryptedData);

void decryptRSA(EVP_PKEY* privateKey, const Data& toDecrypt, Data& oDecryptedData);

void clientSendHomeMade(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);

void serverReceiveHomeMade(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);

void clientSendEnvelope(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);

void serverReceiveEnvelope(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);
