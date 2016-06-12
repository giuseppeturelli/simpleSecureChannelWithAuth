#include <string.h>
#include <iostream>
#include <sys/timeb.h>
#include <chrono>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static const int bufferLength = 2048;
static const int keyLength = 32;
static const int ivLength = 16;

void generateRandomBuffer(unsigned char ioRandBuffer[], int size) {
    RAND_bytes(ioRandBuffer, size);
}

void errorHandle() {
    char error[bufferLength];
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), error, bufferLength);
    std::cout << "Error value: " << error << std::endl;
    exit(1);
}

struct Data {
    unsigned char data[bufferLength];
    int length;
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[ivLength];
};


void encrypt(AESData iAESData, Data toEncrypt, Data& oEncryptedData) {
    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherCtx, 1);

    //START: Message Encryption operation
    int partialLength = 0;
    if (1 != EVP_EncryptInit_ex(cipherCtx, EVP_aes_256_cbc(), NULL, iAESData.key, iAESData.initVector))
        errorHandle();

    if (1 != EVP_EncryptUpdate(cipherCtx, oEncryptedData.data, &partialLength, toEncrypt.data,
        toEncrypt.length))
        errorHandle();
    oEncryptedData.length += partialLength;

    if (1 != EVP_EncryptFinal_ex(cipherCtx, oEncryptedData.data + oEncryptedData.length, &partialLength))
        errorHandle();
    oEncryptedData.length += partialLength;
    //END: Message Encryption operation
}


int main(int argc, char* argv[]) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro, verifyingMicro, decryptionMicro; 
    int ret = -1;
    unsigned char key[keyLength];
    unsigned char initVector[ivLength];
    unsigned char encryptedData[bufferLength];
    unsigned char decryptedData[bufferLength];

    int encryptedDataLength = 0;
    int totLengthEncr = 0;
    int totLengthDecr = 0;
    int decryptedDataLength = 0;

    //Generating key and IV
    generateRandomBuffer(key, sizeof(key));
    generateRandomBuffer(initVector, sizeof(initVector));

    AESData aAESData;
    memcpy(aAESData.key, key, keyLength);
    memcpy(aAESData.initVector, initVector, ivLength);

    //std::string toEncrypt = "u8bZgY4IB0CHtAxNTLpa8oCWji8kvAqFx07Mb3sptkBC9RPS3kOe3w4xVFvv77Go01LG2yXzk300yTTJxNNRzv5BDt2LeWcbqhKgIJli1gjlpgy2yeueLaTrkOBMPKIWq1GNyv3E3k5u8kkQUzDumrUUvu6XZvBstOlWKcni2k3lHD382yaDhwvvPau8Acz7Uucaeg1hTr3G0VB2ESSVssAwzbGgS5OUfA24U2ifSOe4IncxWB8WJF9NXbytoM7gSbF2M20iPRUhtqnTDi4oQxDEUUiySCjKRh2kUNQ6Qv4tAfiMbtei6fOrxF6Ivb6oCCY0E2m2OuIOTPVrvVt0s8x2u6oiElyIwjG7oa70TvLEaFRs6rRRNznHf7WyvTeCn0xCPQwYCWXHzaAnDbNIoQv6XlWkNwry1AZRkESvXg8zqkmCYgY8STBZC1nk5El8yGCFUvSnUM4tDgMUh0cUQDiwcRjzHM5b4ZnvTLcLrZ5g5J8PrHe4zPxquj0BCHD3ghUb0oxSqLALTI0qmfGtXuQ9yiAVL8Pq4lY7aSlvfcP2z5V9xTPOsgb5p6hNEGrj8BfswkXrva5pZ6YmD0nvv6GJhDLC0lbW20XWmVr9RR1XkHXUTmZx7DGvrKoG8SOJnKuYWEoHstqNr11LvowKPuKNEzKN4Octy8kH9yFu3Y007qz5cINSXuJajuuUHcVnK1z45cUikeSwbffBVr2tugmEsMbgZKuNTMgzpu2juK0AQ7Y0N4CNgaXTv96vR0Kr2iBeMGnGlBQ8tSjf6cizPbGQrLkRs96VR8Xp6r3b0i08ywapEAPv38eQHWvu093JZcUTpmp13VzeJK9mvphaYWQmaFJU9i8qkRrI5crFItCh0Z4BSEkvlJwwFMhtQv78AzDjWzfbxDaVS1XSk2p5REDS3PmGx9vQts7W90rJuSxsEiLbNS4hNjKx1YeuvCinoTkhwcAEqx4gpBJT7ucRaNHooOK7eEPM03WzSUne2efWfK6MQrNhXD78N9elDYww";
    std::string toEncrypt = "AllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainx";

    Data aToEncrypt;
    memcpy(aToEncrypt.data, toEncrypt.c_str(), toEncrypt.length());
    aToEncrypt.length = toEncrypt.length();
    
    Data aEncryptedData;

    encrypt(aAESData, aToEncrypt, aEncryptedData);


    //Initialization of cipher context
    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(cipherCtx, 1);

    //START: Message Encryption operation
    start = std::chrono::high_resolution_clock::now();

    if (1 != EVP_EncryptInit_ex(cipherCtx, EVP_aes_256_cbc(), NULL, key, initVector))
        errorHandle();

    if (1 != EVP_EncryptUpdate(cipherCtx, encryptedData, &encryptedDataLength, (unsigned char *) toEncrypt.c_str(),
        toEncrypt.length()))
        errorHandle();
    totLengthEncr += encryptedDataLength;

    if (1 != EVP_EncryptFinal_ex(cipherCtx, encryptedData+encryptedDataLength, &encryptedDataLength))
        errorHandle();
    totLengthEncr += encryptedDataLength;
    end = std::chrono::system_clock::now(); 
    encryptionMicro = end - start;
    //END: Message Encryption operation


    unsigned char signatureData[bufferLength];
    size_t signatureDataLength = sizeof(signatureData);

    //Getting RSA Private key
    FILE* fp;
    EVP_PKEY* privateKey;

    if ((fp = fopen("/etc/ssh/ssh_host_rsa_key", "r")) != NULL) {
        privateKey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
        if (privateKey == NULL)
            exit(1);
        std::cout << "Loaded Private RSA key!" << std::endl;
        fclose(fp);
    } else {
        std::cout << "Private RSA key missing, exiting!" << std::endl;
    }


    //START: Message Signing operation
    start = std::chrono::high_resolution_clock::now();

    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, privateKey))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toEncrypt.c_str(), toEncrypt.length()))
        errorHandle();

    if (1 != EVP_DigestSignFinal(digestSignCtx, signatureData, &signatureDataLength))
        errorHandle();


    std::string signatureDataStr = std::string((const char*)signatureData).substr(0, signatureDataLength);
    end = std::chrono::system_clock::now(); 
    signingMicro = end - start;
    //END: Message Signing operation

    //Getting RSA Public key
    EVP_PKEY* publicKey;
    char error[bufferLength];

    if ((fp = fopen("/etc/ssh/ssh_host_rsa_key_pub", "r")) != NULL) {
        publicKey = PEM_read_PUBKEY(fp, NULL, 0, NULL);
        if (publicKey == NULL)
            exit(1);
        std::cout << "Loaded Public RSA key!" << std::endl;
        fclose(fp);
    } else {
        std::cout << "Public RSA key missing, exiting!" << std::endl;
    }

    //START: Message Verifying operation
    start = std::chrono::high_resolution_clock::now();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, publicKey))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, toEncrypt.c_str(), toEncrypt.length()))
        errorHandle();

    if (EVP_DigestVerifyFinal(digestSignCtx, signatureData, signatureDataLength))
        std::cout << "Signature VERIFIED!" << std::endl;
    else
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    end = std::chrono::system_clock::now(); 
    verifyingMicro = end - start;
    //END: Message Verifying operation


    //START: Decryption operation
    start = std::chrono::high_resolution_clock::now();

    if (1 != EVP_DecryptInit_ex(cipherCtx, EVP_aes_256_cbc(), NULL, key, initVector))
        errorHandle();

    if (1 != EVP_DecryptUpdate(cipherCtx, decryptedData, &decryptedDataLength, encryptedData, totLengthEncr))
        errorHandle();
    totLengthDecr += decryptedDataLength;

    if (1 != EVP_DecryptFinal_ex(cipherCtx, decryptedData+decryptedDataLength, &decryptedDataLength))
        errorHandle();
    totLengthDecr += decryptedDataLength;
    end = std::chrono::system_clock::now(); 
    decryptionMicro = end - start;
    //END: Decryption operation
    

    Data aDecryptedData;
    //START: Decryption operation
    start = std::chrono::high_resolution_clock::now();
    int partialDataLength = 0;

    if (1 != EVP_DecryptInit_ex(cipherCtx, EVP_aes_256_cbc(), NULL, aAESData.key, aAESData.initVector))
        errorHandle();

    if (1 != EVP_DecryptUpdate(cipherCtx, aDecryptedData.data, &partialDataLength, aEncryptedData.data, aEncryptedData.length))
        errorHandle();
    aDecryptedData.length += partialDataLength;

    if (1 != EVP_DecryptFinal_ex(cipherCtx, aDecryptedData.data+aDecryptedData.length, &partialDataLength))
        errorHandle();
    aDecryptedData.length += partialDataLength;
    end = std::chrono::system_clock::now(); 
    decryptionMicro = end - start;
    //END: Decryption operation

    std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
    //std::string decryptedDataStr = std::string((const char*)decryptedData).substr(0, totLengthDecr);
    std::cout << "This after decryption: " << decryptedDataStr << std::endl;


    std::cout << "Encryption time in microseconds: " << encryptionMicro.count() << " Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
    std::cout << "Signing time in microseconds: " << signingMicro.count() << " Verifying Time in microseconds: " << verifyingMicro.count() << std::endl;

    return 0;
}


