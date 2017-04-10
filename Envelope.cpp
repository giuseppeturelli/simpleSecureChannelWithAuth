#include "Envelope.h"

namespace CryptoUtils {

void Envelope::sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData) {
    //Encrypting
    EVP_PKEY* publicKey = _keyMgr.getPublicKeyFor(pubFile[0]);
    envelope_seal(publicKey, dataToSend, oEncryptedData, oAESData);

    //Signing
    _signature.sign(oEncryptedData.encryptedData, oSignatureData);
}

void Envelope::receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData) {
    //Verifying
    bool verified = _signature.verify(receivedData.encryptedData, signatureData);
    
    if (!verified)
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    //Decryption
    envelope_open(receivedData, oDecryptedData, iAESData);
}

void Envelope::sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData) {
    //Encrypting
    EVP_PKEY* publicKey = _keyMgr.getPublicKeyFor(pubFile[0]);
    envelope_seal(publicKey, dataToSend, oEncryptedData, oAESData);
}

void Envelope::receiveEnvelope(Data& iAESData, const EncryptedData& receivedData, Data& oDecryptedData) {
    //Decryption
    envelope_open(receivedData, oDecryptedData, iAESData);
}

void Envelope::envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, EncryptedData& oEncryptedData, Data& oAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;
    int keyLength = 0;

    oAESData.resize(EVP_PKEY_size(publicKey));
    oEncryptedData.initVector.resize(EVP_MAX_IV_LENGTH);

    unsigned char* aAESkeyList[numOfAsymmetricKeypairs];
    aAESkeyList[0] = oAESData.dataPtr();

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (!EVP_SealInit(ctx, EVP_aes_128_cbc(), aAESkeyList, &keyLength, oEncryptedData.initVector.dataPtr(), &publicKey, numOfAsymmetricKeypairs))
        errorHandle();

    oAESData.resize(keyLength);

    //Size
    oEncryptedData.encryptedData.resize(toEncrypt.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_SealUpdate(ctx, oEncryptedData.encryptedData.dataPtr(), &partialLength, toEncrypt.dataPtr(), toEncrypt.size()))
        errorHandle();
    totLength = partialLength;

    if (1 != EVP_SealFinal(ctx, oEncryptedData.encryptedData.dataPtr() + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oEncryptedData.encryptedData.resize(totLength);

    EVP_CIPHER_CTX_free(ctx);
}

void Envelope::envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;

    oDecryptedData.resize(encryptedData.encryptedData.size());

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), iAESData.dataPtr(), iAESData.size(), encryptedData.initVector.dataPtr(), _keyMgr.getThePrivateKey()))
       errorHandle();


    if (1 != EVP_OpenUpdate(ctx, oDecryptedData.dataPtr(), &partialLength, encryptedData.encryptedData.dataPtr(), encryptedData.encryptedData.size()))
        errorHandle();

    totLength = partialLength;

    if (1 != EVP_OpenFinal(ctx, oDecryptedData.dataPtr() + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oDecryptedData.resize(totLength);

    EVP_CIPHER_CTX_free(ctx);
}

}//namespace CryptoUtils
