#include "Crypto.h"
#include <string.h>
#include <iostream>
#include <sys/timeb.h>
#include <chrono>
#include <vector>

#include <openssl/rand.h>
#include <openssl/err.h>


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

void CryptoCollection::envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData) {
    EVP_CIPHER_CTX* ctx;
    int partialLength = 0;

    oAESData.key = (unsigned char *) malloc(EVP_PKEY_size(publicKey[0]));
    memset(oAESData.key, 0, EVP_PKEY_size(publicKey[0]));

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (!EVP_SealInit(ctx, EVP_aes_128_cbc(), &oAESData.key, &oAESData.length, oAESData.initVector, publicKey, 1))
        errorHandle();

    //Size discovery
    oEncryptedData.data = (unsigned char *) malloc(toEncrypt.length + EVP_MAX_BLOCK_LENGTH);
    memset(oEncryptedData.data, 0, toEncrypt.length + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_SealUpdate(ctx, oEncryptedData.data, &partialLength, toEncrypt.data, toEncrypt.length))
        errorHandle();
    oEncryptedData.length += partialLength;

    if (1 != EVP_SealFinal(ctx, oEncryptedData.data + oEncryptedData.length, &partialLength))
        errorHandle();
    oEncryptedData.length += partialLength;

    EVP_CIPHER_CTX_free(ctx);
}

void CryptoCollection::envelope_open(const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int partialLength = 0;

    oDecryptedData.data = (unsigned char *) malloc(encryptedData.length);
    memset(oDecryptedData.data, 0, encryptedData.length);

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), iAESData.key, iAESData.length, iAESData.initVector, privateKey))
       errorHandle();


    if (1 != EVP_OpenUpdate(ctx, oDecryptedData.data, &partialLength, encryptedData.data, encryptedData.length))
        errorHandle();
    oDecryptedData.length += partialLength;

    if (1 != EVP_OpenFinal(ctx, oDecryptedData.data + oDecryptedData.length, &partialLength))
        errorHandle();
    oDecryptedData.length += partialLength;

    EVP_CIPHER_CTX_free(ctx);
}

void CryptoCollection::encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    //START: Message Encryption operation
    int partialLength = 0;
    if (1 != EVP_EncryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.key, iAESData.initVector))
        errorHandle();

    if (1 != EVP_EncryptUpdate(cipherCtx, oEncryptedData.data, &partialLength, toEncrypt.data,
        toEncrypt.length))
        errorHandle();
    oEncryptedData.length += partialLength;

    if (1 != EVP_EncryptFinal_ex(cipherCtx, oEncryptedData.data + oEncryptedData.length, &partialLength))
        errorHandle();
    oEncryptedData.length += partialLength;
    //END: Message Encryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherCtx, 1);

    //START: Decryption operation
    int partialDataLength = 0;

    if (1 != EVP_DecryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.key, iAESData.initVector))
        errorHandle();

    if (1 != EVP_DecryptUpdate(cipherCtx, oDecryptedData.data, &partialDataLength, toDecrypt.data, toDecrypt.length))
        errorHandle();
    oDecryptedData.length += partialDataLength;

    if (1 != EVP_DecryptFinal_ex(cipherCtx, oDecryptedData.data+oDecryptedData.length, &partialDataLength))
        errorHandle();
    oDecryptedData.length += partialDataLength;
    //END: Decryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::sign(const Data& toSign, Data& oSignatureData) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, privateKey))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toSign.data, toSign.length))
        errorHandle();

    //Size discovery
    if (1 != EVP_DigestSignFinal(digestSignCtx, NULL, (size_t*) &oSignatureData.length))
        errorHandle();

    oSignatureData.data = (unsigned char *) malloc(oSignatureData.length);
    memset(oSignatureData.data, 0, oSignatureData.length);


    if (1 != EVP_DigestSignFinal(digestSignCtx, oSignatureData.data, (size_t*) &oSignatureData.length))
        errorHandle();
    EVP_MD_CTX_destroy(digestSignCtx);
    //END: Message Signing operation
}

bool CryptoCollection::verify(const Data& signedData, const Data& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, publicKey))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.data, signedData.length))
        return false;

    bool ret = EVP_DigestVerifyFinal(digestSignCtx, signatureData.data, signatureData.length);
    
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
    if (1 != EVP_PKEY_encrypt(ctx, NULL, (size_t*) &oEncryptedData.length, toEncrypt.data, (size_t) toEncrypt.length))
        errorHandle();

    oEncryptedData.data = (unsigned char *) malloc(oEncryptedData.length);
    memset(oEncryptedData.data, 0, oEncryptedData.length);


    if (1 != EVP_PKEY_encrypt(ctx, oEncryptedData.data, (size_t*) &oEncryptedData.length, toEncrypt.data, (size_t) toEncrypt.length))
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
    if (1 != EVP_PKEY_decrypt(ctx, NULL, (size_t*) &oDecryptedData.length, toDecrypt.data, (size_t) toDecrypt.length))
        errorHandle();

    if (1 != EVP_PKEY_decrypt(ctx, oDecryptedData.data, (size_t*) &oDecryptedData.length, toDecrypt.data, (size_t) toDecrypt.length))
        errorHandle();

    EVP_PKEY_CTX_free(ctx);
}

void CryptoCollection::sendHomeMade(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, encryptionRSAMicro, signingMicro;
    unsigned char key[keyLength];
    unsigned char initVector[EVP_MAX_IV_LENGTH];

    //Generating key and IV
    generateRandomBuffer(key, sizeof(key));
    generateRandomBuffer(initVector, sizeof(initVector));

    Data toEncryptAESData;
    memcpy(toEncryptAESData.data, key, keyLength);

    Data encryptedAESData;

    //Encrypting Key Data
    start = std::chrono::high_resolution_clock::now();
    encryptRSA(toEncryptAESData, encryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    encryptionRSAMicro = end - start;

    oAESData.key = (unsigned char *) malloc(encryptedAESData.length);
    memcpy(oAESData.key, encryptedAESData.data, encryptedAESData.length);
    oAESData.length = encryptedAESData.length;
    memcpy(oAESData.initVector, initVector, EVP_MAX_IV_LENGTH);

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

    Data encryptedAESData(iAESData.length);
    memcpy(encryptedAESData.data, iAESData.key, iAESData.length);

    //Decrypting Key Data
    start = std::chrono::high_resolution_clock::now();
    decryptRSA(encryptedAESData, decryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    decryptionRSAMicro = end - start;

    memcpy(iAESData.key, decryptedAESData.data, decryptedAESData.length);
    iAESData.length = decryptedAESData.length;

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
    envelope_seal(&publicKey, dataToSend, oEncryptedData, oAESData);
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
