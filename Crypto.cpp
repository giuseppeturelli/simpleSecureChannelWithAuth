#include "Crypto.h"
#include <string.h>
#include <iostream>
#include <fstream>
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
    loadAESKey(aesFile);
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

void CryptoCollection::loadAESKey(std::string keyFilePath) {
    std::ifstream infile(keyFilePath);
    std::string line;
    if (!std::getline(infile, line) || line.length() > 2*AESkeyLength) {
        std::cout << "AES key missing or too long!" << std::endl;
    } else {
        size_t oSize;
        theAESKey.resize(AESkeyLength);
        aB64.decodeBase64FromStringToChar(line, (char *)theAESKey.dataPtr(), &oSize);
    }
}

void CryptoCollection::envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, EncryptedData& oEncryptedData, Data& oAESData) {
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

void CryptoCollection::envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;

    oDecryptedData.resize(encryptedData.encryptedData.size());

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), iAESData.dataPtr(), iAESData.size(), encryptedData.initVector.dataPtr(), privateKey))
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

void CryptoCollection::encryptAES(const Data& iAESData, const Data& toEncrypt, EncryptedData& oEncryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    BaseSixtyFour aB64;

    oEncryptedData.encryptedData.resize(toEncrypt.size());

    //START: Message Encryption operation
    int totLength = 0;
    int partialLength = 0;
    if (1 != EVP_EncryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.dataPtr(), oEncryptedData.initVector.dataPtr()))
        errorHandle();


    if (1 != EVP_EncryptUpdate(cipherCtx, oEncryptedData.encryptedData.dataPtr(), &partialLength, toEncrypt.dataPtr(), toEncrypt.size()))
        errorHandle();
    totLength += partialLength;

    if (1 != EVP_EncryptFinal_ex(cipherCtx, oEncryptedData.encryptedData.dataPtr() + partialLength, &partialLength))
        errorHandle();

    oEncryptedData.encryptedData.resize(totLength);
    //END: Message Encryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::decryptAES(const Data& iAESData, const EncryptedData& toDecrypt, Data& oDecryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherCtx, 1);

    oDecryptedData.resize(toDecrypt.encryptedData.size());

    //START: Decryption operation
    int totLength = 0;
    int partialLength = 0;

    if (1 != EVP_DecryptInit_ex(cipherCtx, EVP_aes_128_cbc(), NULL, iAESData.dataPtr(), toDecrypt.initVector.dataPtr()))
        errorHandle();


    if (1 != EVP_DecryptUpdate(cipherCtx, oDecryptedData.dataPtr(), &partialLength, toDecrypt.encryptedData.dataPtr(),
        toDecrypt.encryptedData.size()))
        errorHandle();
    totLength = partialLength;

    if (1 != EVP_DecryptFinal_ex(cipherCtx, oDecryptedData.dataPtr() + partialLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oDecryptedData.resize(totLength);
    //END: Decryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoCollection::sign(const EncryptedData& toSign, Data& oSignatureData) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, privateKey))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toSign.encryptedData.dataPtr(), toSign.encryptedData.size()))
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

bool CryptoCollection::verify(const EncryptedData& signedData, const Data& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, publicKey))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.encryptedData.dataPtr(), signedData.encryptedData.size()))
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

void CryptoCollection::sendHomeMade(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, encryptionRSAMicro, signingMicro;


    //Generating key and IV
    oAESData.resize(16);
    oEncryptedData.initVector.resize(EVP_MAX_IV_LENGTH);
    generateRandomBuffer(oAESData.dataPtr(), 16);
    generateRandomBuffer(oEncryptedData.initVector.dataPtr(), EVP_MAX_IV_LENGTH);

    Data encryptedAESData;
    //Encrypting Key Data
    start = std::chrono::high_resolution_clock::now();
    encryptRSA(oAESData, encryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    encryptionRSAMicro = end - start;


    oAESData.resize(encryptedAESData.size());
    oAESData = encryptedAESData;

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

void CryptoCollection::receiveHomeMade(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData) {
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
    decryptRSA(iAESData, decryptedAESData);
    end = std::chrono::high_resolution_clock::now();
    decryptionRSAMicro = end - start;

    iAESData = decryptedAESData;

    //Decryption
    start = std::chrono::high_resolution_clock::now();
    decryptAES(iAESData, receivedData, oDecryptedData);
    end = std::chrono::high_resolution_clock::now();
    decryptionMicro = end - start;

    std::cout << "Verifying Time in microseconds: " << verifyingMicro.count() << std::endl << "DecryptionRSA Time in microseconds: " << decryptionRSAMicro.count() << std::endl << "Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
}

void CryptoCollection::sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData) {
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

void CryptoCollection::receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData) {
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

std::string CryptoCollection::encryptAESString(const std::string& stringToEncrypt) {
    Data toEncryptData;
    toEncryptData.resize(stringToEncrypt.length());
    memcpy(toEncryptData.dataPtr(), stringToEncrypt.c_str(), stringToEncrypt.length());

    EncryptedData encryptedData;
    encryptedData.initVector.resize(EVP_MAX_IV_LENGTH);
    encryptedData.encryptedData.resize(stringToEncrypt.length());
    generateRandomBuffer(encryptedData.initVector.dataPtr(), EVP_MAX_IV_LENGTH);

    encryptAES(theAESKey, toEncryptData, encryptedData);
    Data ivAndEncryptedData;
    ivAndEncryptedData.resize(encryptedData.initVector.size()+encryptedData.encryptedData.size());
    memcpy(ivAndEncryptedData.dataPtr(), encryptedData.initVector.dataPtr(), encryptedData.initVector.size());
    memcpy(ivAndEncryptedData.dataPtr()+encryptedData.initVector.size(), encryptedData.encryptedData.dataPtr(), encryptedData.encryptedData.size());

    return aB64.encodeBase64FromCharToString((char *)ivAndEncryptedData.dataPtr(), ivAndEncryptedData.size());
}

std::string CryptoCollection::decryptAESString(const std::string& base64StringToDecrypt) {
    
    Data unbase64Data;
    unbase64Data.resize(base64StringToDecrypt.length());
    size_t oLength = 0;
    aB64.decodeBase64FromStringToChar(base64StringToDecrypt, (char *)unbase64Data.dataPtr(), &oLength);
    unbase64Data.resize(oLength);

    EncryptedData toDecrypt;
    toDecrypt.initVector.resize(EVP_MAX_IV_LENGTH);
    toDecrypt.encryptedData.resize(unbase64Data.size()-EVP_MAX_BLOCK_LENGTH);

    memcpy(toDecrypt.initVector.dataPtr(), unbase64Data.dataPtr(), EVP_MAX_BLOCK_LENGTH);
    memcpy(toDecrypt.encryptedData.dataPtr(), unbase64Data.dataPtr()+EVP_MAX_BLOCK_LENGTH, unbase64Data.size()-EVP_MAX_BLOCK_LENGTH);

    Data decryptedData;
    decryptedData.resize(toDecrypt.encryptedData.size());

    decryptAES(theAESKey, toDecrypt, decryptedData);

    decryptedData.resize(decryptedData.size()+1);
    decryptedData.dataPtr()[decryptedData.size()-1] = '\0';

    std::string decryptedString((char *)decryptedData.dataPtr());
    return decryptedString;
}

}//namespace CryptoUtils
