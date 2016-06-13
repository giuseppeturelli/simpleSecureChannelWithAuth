#include <string.h>
#include <iostream>
#include <sys/timeb.h>
#include <chrono>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static const int bufferLength = 2048;
static const int keyLength = 16;
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
    long unsigned int length = 0;
    long unsigned int availableSpace = bufferLength;
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[ivLength];
    int length = 0;
};

void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData) {
    EVP_CIPHER_CTX* ctx;
    int partialLength = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();
$
    if (1 != EVP_SealInit(ctx, EVP_aes_128_cbc(), (unsigned char **) &oAESData.key, &oAESData.length, oAESData.initVector, publicKey, 1))
        errorHandle();

    if (1 != EVP_SealUpdate(ctx, oEncryptedData.data, &partialLength, toEncrypt.data, toEncrypt.length))
        errorHandle();
    oEncryptedData.length += partialLength;

    if (1 != EVP_SealFinal(ctx, oEncryptedData.data + oEncryptedData.length, &partialLength))
        errorHandle();
    oEncryptedData.length += partialLength;

    EVP_CIPHER_CTX_free(ctx);
}

void envelope_open(EVP_PKEY* privateKey, const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int partialLength = 0;

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

void encrypt(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData) {
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

void decrypt(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData) {
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

void sign(EVP_PKEY* privateKey, const Data& toSign, Data& oSignatureData) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, privateKey))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toSign.data, toSign.length))
        errorHandle();

    if (1 != EVP_DigestSignFinal(digestSignCtx, NULL, (size_t*) &oSignatureData.length))
        errorHandle();

    if (1 != EVP_DigestSignFinal(digestSignCtx, oSignatureData.data, (size_t*) &oSignatureData.length))
        errorHandle();
    EVP_MD_CTX_cleanup(digestSignCtx);
    //END: Message Signing operation
}

bool verify(EVP_PKEY* publicKey, const Data& signedData, const Data& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, publicKey))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.data, signedData.length))
        errorHandle();

    bool ret = EVP_DigestVerifyFinal(digestSignCtx, signatureData.data, signatureData.length);
    EVP_MD_CTX_cleanup(digestSignCtx);

    return ret;
    //END: Message Verifying operation
}

int main(int argc, char* argv[]) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro, verifyingMicro, decryptionMicro;
    int ret = -1;
    unsigned char key[keyLength];
    unsigned char initVector[ivLength];

    //Generating key and IV
    generateRandomBuffer(key, sizeof(key));
    generateRandomBuffer(initVector, sizeof(initVector));

    AESData aAESData;
    memcpy(aAESData.key, key, keyLength);
    memcpy(aAESData.initVector, initVector, ivLength);

    //std::string toEncrypt = "u8bZgY4IB0CHtAxNTLpa8oCWji8kvAqFx07Mb3sptkBC9RPS3kOe3w4xVFvv77Go01LG2yXzk300yTTJxNNRzv5BDt2LeWcbqhKgIJli1gjlpgy2yeueLaTrkOBMPKIWq1GNyv3E3k5u8kkQUzDumrUUvu6XZvBstOlWKcni2k3lHD382yaDhwvvPau8Acz7Uucaeg1hTr3G0VB2ESSVssAwzbGgS5OUfA24U2ifSOe4IncxWB8WJF9NXbytoM7gSbF2M20iPRUhtqnTDi4oQxDEUUiySCjKRh2kUNQ6Qv4tAfiMbtei6fOrxF6Ivb6oCCY0E2m2OuIOTPVrvVt0s8x2u6oiElyIwjG7oa70TvLEaFRs6rRRNznHf7WyvTeCn0xCPQwYCWXHzaAnDbNIoQv6XlWkNwry1AZRkESvXg8zqkmCYgY8STBZC1nk5El8yGCFUvSnUM4tDgMUh0cUQDiwcRjzHM5b4ZnvTLcLrZ5g5J8PrHe4zPxquj0BCHD3ghUb0oxSqLALTI0qmfGtXuQ9yiAVL8Pq4lY7aSlvfcP2z5V9xTPOsgb5p6hNEGrj8BfswkXrva5pZ6YmD0nvv6GJhDLC0lbW20XWmVr9RR1XkHXUTmZx7DGvrKoG8SOJnKuYWEoHstqNr11LvowKPuKNEzKN4Octy8kH9yFu3Y007qz5cINSXuJajuuUHcVnK1z45cUikeSwbffBVr2tugmEsMbgZKuNTMgzpu2juK0AQ7Y0N4CNgaXTv96vR0Kr2iBeMGnGlBQ8tSjf6cizPbGQrLkRs96VR8Xp6r3b0i08ywapEAPv38eQHWvu093JZcUTpmp13VzeJK9mvphaYWQmaFJU9i8qkRrI5crFItCh0Z4BSEkvlJwwFMhtQv78AzDjWzfbxDaVS1XSk2p5REDS3PmGx9vQts7W90rJuSxsEiLbNS4hNjKx1YeuvCinoTkhwcAEqx4gpBJT7ucRaNHooOK7eEPM03WzSUne2efWfK6MQrNhXD78N9elDYww";
    std::string toEncrypt = "AllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainx";
    //Getting RSA Private key
    FILE* fp;
    EVP_PKEY* privateKey;

    if ((fp = fopen("/etc/ssh/ssh_host_rsa_key", "r")) != NULL) {
        privateKey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
        if (privateKey == NULL)
            errorHandle();
        std::cout << "Loaded Private RSA key!" << std::endl;
        fclose(fp);
    } else {
        std::cout << "Private RSA key missing, exiting!" << std::endl;
    }
    //Getting RSA Public key
    EVP_PKEY* publicKey;

    if ((fp = fopen("/etc/ssh/ssh_host_rsa_key_pub", "r")) != NULL) {
        publicKey = PEM_read_PUBKEY(fp, NULL, 0, NULL);
        if (publicKey == NULL)
            errorHandle();

        std::cout << "Loaded Public RSA key!" << std::endl;
        fclose(fp);
    } else {
        std::cout << "Public RSA key missing, exiting!" << std::endl;
        exit(1);
    }

    Data aToEncrypt;
    memcpy(aToEncrypt.data, toEncrypt.c_str(), toEncrypt.length());
    aToEncrypt.length = toEncrypt.length();


    /*
    //Encrypting
    Data aEncryptedData;
    AESData aAESData;
    envelope_seal(&privateKey, aToEncrypt, aEncryptedData, aAESData);
    */
    //Encrypting
    Data aEncryptedData;
    start = std::chrono::high_resolution_clock::now();
    encrypt(aAESData, aToEncrypt, aEncryptedData);
    end = std::chrono::system_clock::now();
    encryptionMicro = end - start;

    //Signing
    Data aSignatureData;
    start = std::chrono::high_resolution_clock::now();
    sign(privateKey, aEncryptedData, aSignatureData);
    end = std::chrono::system_clock::now();
    signingMicro = end - start;


    //Verifying
    start = std::chrono::high_resolution_clock::now();
    bool verified= verify(publicKey, aEncryptedData, aSignatureData);
    end = std::chrono::system_clock::now();
    verifyingMicro = end - start;


    if (verified)
        std::cout << "Signature VERIFIED!" << std::endl;
    else
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    /*
    //Decryption
    Data aDecryptedData;
    envelope_open(publicKey, aEncryptedData, aDecryptedData, aAESData);
    */

    //Decryption
    Data aDecryptedData;
    start = std::chrono::high_resolution_clock::now();
    decrypt(aAESData, aEncryptedData, aDecryptedData);
    end = std::chrono::system_clock::now();
    decryptionMicro = end - start;

    std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
    //std::string decryptedDataStr = std::string((const char*)decryptedData).substr(0, totLengthDecr);
    std::cout << "This after decryption: " << decryptedDataStr << std::endl;


    std::cout << "Encryption time in microseconds: " << encryptionMicro.count() << " Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
    std::cout << "Signing time in microseconds: " << signingMicro.count() << " Verifying Time in microseconds: " << verifyingMicro.count() << std::endl;

    return 0;
}

