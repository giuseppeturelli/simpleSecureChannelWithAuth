#include "Crypto.h"
#include "BaseSixtyFour.h"
#include <string.h>
#include <iostream>
#include <sys/timeb.h>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <algorithm>

namespace CryptoUtils {

Data::Data(int size) {
    data_.resize(size);
}

unsigned char* Data::dataPtr() {
    return &data_[0];
}

const unsigned char* Data::dataPtr() const {
    return &data_[0];
}

void Data::resize(int size) {
    data_.resize(size);
}

int Data::size() {
    return data_.size();
}

const int Data::size() const {
    return data_.size();
}

bool Data::equal(const Data& toCompare) {
    return std::equal(data_.begin(), data_.end(), toCompare.data_.begin());
}

CryptoCollection::CryptoCollection() {
    loadKeys();
}

CryptoCollection::~CryptoCollection() {
    unloadKeys();
}

void CryptoCollection::printAverage() {
    if (messagesReceived > 0)
        std::cout << std::endl << "Messages Handled: " << messagesReceived << std::endl;

    if (!encryptTime.empty())
        std::cout << "Average Encrypt time microsec: " << std::accumulate(encryptTime.begin(), encryptTime.end(), 0.0)/encryptTime.size() << std::endl;

    if (!signTime.empty())
        std::cout << "Average Sign time microsec: " << std::accumulate(signTime.begin(), signTime.end(), 0.0)/signTime.size() << std::endl;

    if (!verifyTime.empty())
        std::cout << "Average Verify time microsec: " << std::accumulate(verifyTime.begin(), verifyTime.end(), 0.0)/verifyTime.size() << std::endl;

    if (!decryptTime.empty())
        std::cout << "Average Decrypt time microsec: " << std::accumulate(decryptTime.begin(), decryptTime.end(), 0.0)/decryptTime.size() << std::endl;

}

void CryptoCollection::loadKeys() {

    auto it = privFile.begin();
    for (; it != privFile.end();++it) {
        loadPrivKey(*it);
    }
    it = pubFile.begin();
    for (; it != pubFile.end();++it) {
        loadPubKey(*it);
    }
}

void CryptoCollection::unloadKeys() {
    auto it = keys.begin();
    for (;it != keys.end();++it) {
        EVP_PKEY_free(it->second);
    }
}

void CryptoCollection::loadPubKey(std::string keyFilePath) {
    FILE* fp;
    EVP_PKEY* loadedKey = NULL;
    if ((fp = fopen(keyFilePath.c_str(), "r")) != NULL) {
        loadedKey = PEM_read_PUBKEY(fp, NULL, 0, NULL);
        if (loadedKey == NULL)
            std::cout << "Failed to load key!" << std::endl;
        fclose(fp);
        keys[keyFilePath] = loadedKey;
    } else {
        std::cout << "RSA key missing!" << std::endl;
    }
}

void CryptoCollection::loadPrivKey(std::string keyFilePath) {
    FILE* fp;
    EVP_PKEY* loadedKey = NULL;
    if ((fp = fopen(keyFilePath.c_str(), "r")) != NULL) {
        loadedKey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
        if (loadedKey == NULL)
            std::cout << "Failed to load key!" << std::endl;
        fclose(fp);
        keys[keyFilePath] = loadedKey;
    } else {
        std::cout << "RSA key missing!" << std::endl;
    }
}

void CryptoCollection::setPrivateKey(const std::string& keyFilePath) {
    privateKey = keys[keyFilePath];
}

void CryptoCollection::setPublicKey(const std::string& keyFilePath) {
    publicKey = keys[keyFilePath];
}

void CryptoCollection::generateRandomBuffer(unsigned char* ioRandBuffer, int size) {
    RAND_bytes(ioRandBuffer, size);
}

void CryptoCollection::errorHandle() {
    char error[1024];
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), error, 1024);
    std::cout << "Error value: " << error << std::endl;
    exit(1);
}

void CryptoCollection::envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;
    int keyLength = 0;

    oAESData.key.resize(EVP_PKEY_size(publicKey));
    oAESData.initVector.resize(EVP_MAX_IV_LENGTH);

    unsigned char* aAESkeyList[numOfAsymmetricKeypairs];
    aAESkeyList[0] = oAESData.key.dataPtr();

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (!EVP_SealInit(ctx, EVP_aes_128_cbc(), aAESkeyList, &keyLength, oAESData.initVector.dataPtr(), &publicKey, numOfAsymmetricKeypairs))
        errorHandle();

    oAESData.key.resize(keyLength);

    //Size
    oEncryptedData.resize(toEncrypt.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_SealUpdate(ctx, oEncryptedData.dataPtr(), &partialLength, toEncrypt.dataPtr(), toEncrypt.size()))
        errorHandle();
    totLength = partialLength;

    if (1 != EVP_SealFinal(ctx, oEncryptedData.dataPtr() + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oEncryptedData.resize(totLength);

    EVP_CIPHER_CTX_free(ctx);
}

void CryptoCollection::envelope_open(const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;

    oDecryptedData.resize(encryptedData.size());

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), iAESData.key.dataPtr(), iAESData.key.size(), iAESData.initVector.dataPtr(), privateKey))
       errorHandle();


    if (1 != EVP_OpenUpdate(ctx, oDecryptedData.dataPtr(), &partialLength, encryptedData.dataPtr(), encryptedData.size()))
        errorHandle();

    totLength = partialLength;

    if (1 != EVP_OpenFinal(ctx, oDecryptedData.dataPtr() + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oDecryptedData.resize(totLength);

    EVP_CIPHER_CTX_free(ctx);
}

void CryptoCollection::encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    BaseSixtyFour aB64;

    oEncryptedData.resize(toEncrypt.size());

    //START: Message Encryption operation
    int totLength = 0;
    int partialLength = 0;
    if (1 != EVP_EncryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.key.dataPtr(), iAESData.initVector.dataPtr()))
        errorHandle();


    if (1 != EVP_EncryptUpdate(cipherCtx, oEncryptedData.dataPtr(), &partialLength, toEncrypt.dataPtr(), toEncrypt.size()))
        errorHandle();
    totLength += partialLength;

    if (1 != EVP_EncryptFinal_ex(cipherCtx, oEncryptedData.dataPtr() + partialLength, &partialLength))
        errorHandle();

    oEncryptedData.resize(totLength);
    //END: Message Encryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherCtx, 1);

    oDecryptedData.resize(toDecrypt.size());

    //START: Decryption operation
    int totLength = 0;
    int partialLength = 0;

    if (1 != EVP_DecryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.key.dataPtr(), iAESData.initVector.dataPtr()))
        errorHandle();


    if (1 != EVP_DecryptUpdate(cipherCtx, oDecryptedData.dataPtr(), &partialLength, toDecrypt.dataPtr(),
        toDecrypt.size()))
        errorHandle();
    totLength = partialLength;

    if (1 != EVP_DecryptFinal_ex(cipherCtx, oDecryptedData.dataPtr() + partialLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oDecryptedData.resize(totLength);
    //END: Decryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::sign(const Data& toSign, Data& oSignatureData) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, privateKey))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toSign.dataPtr(), toSign.size()))
        errorHandle();

    //Size discovery
    int foreseenLength = 0;
    if (1 != EVP_DigestSignFinal(digestSignCtx, NULL, (size_t*) &foreseenLength))
        errorHandle();

    oSignatureData.resize(foreseenLength);

    int finalLength = foreseenLength;
    if (1 != EVP_DigestSignFinal(digestSignCtx, oSignatureData.dataPtr(), (size_t*) &finalLength))
        errorHandle();

    oSignatureData.resize(finalLength);
    EVP_MD_CTX_destroy(digestSignCtx);
    //END: Message Signing operation
}

bool CryptoCollection::verify(const Data& signedData, const Data& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, publicKey))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.dataPtr(), signedData.size()))
        return false;

    bool ret = EVP_DigestVerifyFinal(digestSignCtx, signatureData.dataPtr(), signatureData.size());

    EVP_MD_CTX_destroy(digestSignCtx);

    return ret;
    //END: Message Verifying operation
}

//Assumes public key in input
void CryptoCollection::encryptRSA(const Data& toEncrypt, Data& oEncryptedData) {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx)
        errorHandle();

    if (1 != EVP_PKEY_encrypt_init(ctx))
        errorHandle();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        errorHandle();

    //Size discovery
    int foreseenLength = 0;
    if (1 != EVP_PKEY_encrypt(ctx, NULL, (size_t*) &foreseenLength, toEncrypt.dataPtr(), (size_t)
        toEncrypt.size()))
        errorHandle();

    oEncryptedData.resize(foreseenLength);

    int finalLength = 0;
    if (1 != EVP_PKEY_encrypt(ctx, oEncryptedData.dataPtr(), (size_t*) &finalLength, toEncrypt.dataPtr(), (size_t) toEncrypt.size()))
        errorHandle();

    EVP_PKEY_CTX_free(ctx);
}

void CryptoCollection::decryptRSA(const Data& toDecrypt, Data& oDecryptedData) {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
        errorHandle();

    if (1 != EVP_PKEY_decrypt_init(ctx))
        errorHandle();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        errorHandle();

    //Size discovery
    int foreseenLength = 0;
    if (1 != EVP_PKEY_decrypt(ctx, NULL, (size_t*) &foreseenLength, toDecrypt.dataPtr(), (size_t) toDecrypt.size()))
        errorHandle();

    oDecryptedData.resize(foreseenLength);

    int finalLength = 0;
    if (1 != EVP_PKEY_decrypt(ctx, oDecryptedData.dataPtr(), (size_t*) &finalLength, toDecrypt.dataPtr(), (size_t) toDecrypt.size()))
        errorHandle();

    EVP_PKEY_CTX_free(ctx);
}

void CryptoCollection::sendHomeMade(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, encryptionRSAMicro, signingMicro;


    //Generating key and IV
    oAESData.key.resize(16);
    oAESData.initVector.resize(EVP_MAX_IV_LENGTH);
    generateRandomBuffer(oAESData.key.dataPtr(), 16);
    generateRandomBuffer(oAESData.initVector.dataPtr(), EVP_MAX_IV_LENGTH);

    Data encryptedAESData;
    //Encrypting Key Data
    start = std::chrono::high_resolution_clock::now();
    encryptRSA(oAESData.key, encryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    encryptionRSAMicro = end - start;


    oAESData.key.resize(encryptedAESData.size());
    oAESData.key = encryptedAESData;

    //Encrypting Message Data
    start = std::chrono::high_resolution_clock::now();
    encryptAES(oAESData, dataToSend, oEncryptedData);
    end = std::chrono::high_resolution_clock::now();
    encryptionMicro = end - start;

    //Signing
    Data aSignatureData;
    start = std::chrono::high_resolution_clock::now();
    sign(oEncryptedData, oSignatureData);
    end = std::chrono::high_resolution_clock::now();
    signingMicro = end - start;

    std::cout << "EncryptionRSA time in microseconds: " << encryptionRSAMicro.count() << std::endl << "EncryptionAES time in microseconds: " << encryptionMicro.count() << std::endl << "Signing time in microseconds: " << signingMicro.count() << std::endl;
}

void CryptoCollection::receiveHomeMade(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> verifyingMicro, decryptionMicro, decryptionRSAMicro;

    //Verifying
    start = std::chrono::high_resolution_clock::now();
    bool verified = verify(receivedData, signatureData);
    end = std::chrono::high_resolution_clock::now();
    verifyingMicro = end - start;

    if (!verified)
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    Data decryptedAESData;

    //Decrypting Key Data
    start = std::chrono::high_resolution_clock::now();
    decryptRSA(iAESData.key, decryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    decryptionRSAMicro = end - start;

    iAESData.key = decryptedAESData;

    //Decryption
    start = std::chrono::high_resolution_clock::now();
    decryptAES(iAESData, receivedData, oDecryptedData);
    end = std::chrono::high_resolution_clock::now();
    decryptionMicro = end - start;

    std::cout << "Verifying Time in microseconds: " << verifyingMicro.count() << std::endl << "DecryptionRSA Time in microseconds: " << decryptionRSAMicro.count() << std::endl << "Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
}

void CryptoCollection::sendEnvelope(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro;

    //Encrypting
    start = std::chrono::high_resolution_clock::now();
    envelope_seal(publicKey, dataToSend, oEncryptedData, oAESData);
    end = std::chrono::high_resolution_clock::now();
    encryptionMicro = end - start;

    encryptTime.push_back(encryptionMicro.count());

    //Signing
    start = std::chrono::high_resolution_clock::now();
    sign(oEncryptedData, oSignatureData);
    end = std::chrono::high_resolution_clock::now();
    signingMicro = end - start;

    signTime.push_back(signingMicro.count());
}

void CryptoCollection::receiveEnvelope(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> verifyingMicro, decryptionMicro;
    messagesReceived++;

    //Verifying
    start = std::chrono::high_resolution_clock::now();
    bool verified = verify(receivedData, signatureData);
    end = std::chrono::high_resolution_clock::now();
    verifyingMicro = end - start;

    verifyTime.push_back(verifyingMicro.count());

    if (!verified)
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    //Decryption
    start = std::chrono::high_resolution_clock::now();
    envelope_open(receivedData, oDecryptedData, iAESData);
    end = std::chrono::high_resolution_clock::now();
    decryptionMicro = end - start;

    decryptTime.push_back(decryptionMicro.count());
}

}//namespace CryptoUtils
