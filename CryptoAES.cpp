#include "CryptoAES.h"
#include <string>
#include <iostream>
#include <fstream>
#include <openssl/rand.h>
#include <openssl/err.h>

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

CryptoAES::CryptoAES() {
    this->loadAESKey(aesFile);
}

CryptoAES::~CryptoAES() {}
void CryptoAES::generateRandomBuffer(unsigned char* ioRandBuffer, int size) {
    RAND_bytes(ioRandBuffer, size);
}

void CryptoAES::errorHandle() {
    char error[1024];
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), error, 1024);
    std::cout << "Error value: " << error << std::endl;
    throw 1;
}

void CryptoAES::loadAESKey(std::string keyFilePath) {
    std::ifstream infile(keyFilePath);
    std::string line;
    if (!std::getline(infile, line) || line.length() > 2*AESkeyLength) {
        std::cout << "AES key missing or too long!" << std::endl;
        std::cout << "A brand new AES key will be generated and stored!" << std::endl;
        this->generateAndStoreAESKey(keyFilePath);
    } else {
        size_t oSize;
        theAESKey.resize(AESkeyLength);
        aB64.decodeBase64FromStringToChar(line, (char *)theAESKey.dataPtr(), &oSize);
    }
    infile.close();
}

void CryptoAES::generateAndStoreAESKey(std::string keyFilePath) {
    std::ofstream outfile(keyFilePath);
    theAESKey.resize(AESkeyLength);
    generateRandomBuffer(theAESKey.dataPtr(), AESkeyLength);
    std::string b64EncodedAESKey = aB64.encodeBase64FromCharToString((char *)theAESKey.dataPtr(), theAESKey.size());
    outfile << b64EncodedAESKey;
    outfile.close();
}

void CryptoAES::encryptAES(const Data& iAESData, const Data& toEncrypt, EncryptedData& oEncryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    oEncryptedData.encryptedData.resize(toEncrypt.size()+EVP_MAX_BLOCK_LENGTH);

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

    totLength += partialLength;
    oEncryptedData.encryptedData.resize(totLength);
    //END: Message Encryption operation
    EVP_CIPHER_CTX_free(cipherCtx);
}

void CryptoAES::decryptAES(const Data& iAESData, const EncryptedData& toDecrypt, Data& oDecryptedData) {
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

std::string CryptoAES::encryptAESString(const std::string& stringToEncrypt) {
    Data toEncryptData(stringToEncrypt.length());
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

std::string CryptoAES::decryptAESString(const std::string& base64StringToDecrypt) {
    
    Data unbase64Data(base64StringToDecrypt.length());
    size_t oLength = 0;
    aB64.decodeBase64FromStringToChar(base64StringToDecrypt, (char *)unbase64Data.dataPtr(), &oLength);
    unbase64Data.resize(oLength);

    EncryptedData toDecrypt;
    toDecrypt.initVector.resize(EVP_MAX_IV_LENGTH);
    toDecrypt.encryptedData.resize(unbase64Data.size()-EVP_MAX_IV_LENGTH);

    memcpy(toDecrypt.initVector.dataPtr(), unbase64Data.dataPtr(), EVP_MAX_IV_LENGTH);
    memcpy(toDecrypt.encryptedData.dataPtr(), unbase64Data.dataPtr()+EVP_MAX_IV_LENGTH, unbase64Data.size()-EVP_MAX_IV_LENGTH);

    Data decryptedData;
    decryptedData.resize(toDecrypt.encryptedData.size());

    decryptAES(theAESKey, toDecrypt, decryptedData);

    decryptedData.resize(decryptedData.size()+1);
    decryptedData.dataPtr()[decryptedData.size()-1] = '\0';

    std::string decryptedString((char *)decryptedData.dataPtr());
    return decryptedString;
}
}//namespace CryptoUtils
