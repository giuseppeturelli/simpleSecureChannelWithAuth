#include <string.h>
#include <iostream>
#include <sys/timeb.h>
#include <chrono>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static const int bufferLength = 2048;
static const int keyLength = 1024;

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
    unsigned char initVector[EVP_MAX_IV_LENGTH];
    int length = 0;
};

void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData) {
    EVP_CIPHER_CTX* ctx;
    int partialLength = 0;
    unsigned char* tempKey;

    tempKey = (unsigned char *) malloc(EVP_PKEY_size(publicKey[0]));

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (!EVP_SealInit(ctx, EVP_aes_128_cbc(), &tempKey, &oAESData.length, oAESData.initVector, publicKey, 1))
        errorHandle();

    if (1 != EVP_SealUpdate(ctx, oEncryptedData.data, &partialLength, toEncrypt.data, toEncrypt.length))
        errorHandle();
    oEncryptedData.length += partialLength;

    if (1 != EVP_SealFinal(ctx, oEncryptedData.data + oEncryptedData.length, &partialLength))
        errorHandle();
    oEncryptedData.length += partialLength;

    memcpy(oAESData.key, tempKey, oAESData.length);
    free(tempKey);

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

void encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData) {
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

void decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData) {
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
    EVP_MD_CTX_destroy(digestSignCtx);
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
    EVP_MD_CTX_destroy(digestSignCtx);

    return ret;
    //END: Message Verifying operation
}

//Assumes public key in input
void encryptRSA(EVP_PKEY* publicKey, const Data& toEncrypt, Data& oEncryptedData) {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx)
        errorHandle();

    if (1 != EVP_PKEY_encrypt_init(ctx))
        errorHandle();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        errorHandle();

    if (1 != EVP_PKEY_encrypt(ctx, oEncryptedData.data, (size_t*) &oEncryptedData.length, toEncrypt.data, (size_t) toEncrypt.length))
        errorHandle();

    //Cleanup needed
}

void decryptRSA(EVP_PKEY* privateKey, const Data& toDecrypt, Data& oDecryptedData) {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
        errorHandle();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        errorHandle();

    if (1 != EVP_PKEY_decrypt_init(ctx))
        errorHandle();

    if (1 != EVP_PKEY_decrypt(ctx, oDecryptedData.data, (size_t*) &oDecryptedData.length, toDecrypt.data, (size_t) toDecrypt.length))
        errorHandle();

    //Cleanup needed
}

void clientSendHomeMade(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro;
    unsigned char key[keyLength];
    unsigned char initVector[EVP_MAX_IV_LENGTH];

    //Generating key and IV
    generateRandomBuffer(key, sizeof(key));
    generateRandomBuffer(initVector, sizeof(initVector));

    memcpy(oAESData.key, key, keyLength);
    memcpy(oAESData.initVector, initVector, EVP_MAX_IV_LENGTH);

    //Encrypting Message Data
    start = std::chrono::high_resolution_clock::now();
    encryptAES(oAESData, dataToSend, oEncryptedData);
    end = std::chrono::high_resolution_clock::now();
    encryptionMicro = end - start;

    //Signing
    Data aSignatureData;
    start = std::chrono::high_resolution_clock::now();
    sign(privateKey, oEncryptedData, oSignatureData);
    end = std::chrono::high_resolution_clock::now();
    signingMicro = end - start;

    std::cout << "Encryption time in microseconds: " << encryptionMicro.count() << std::endl << "Signing time in microseconds: " << signingMicro.count() << std::endl;
}

void serverReceiveHomeMade(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> verifyingMicro, decryptionMicro;

    //Verifying
    start = std::chrono::high_resolution_clock::now();
    bool verified = verify(publicKey, receivedData, signatureData);
    end = std::chrono::high_resolution_clock::now();
    verifyingMicro = end - start;

    if (verified)
        std::cout << "Signature VERIFIED!" << std::endl;
    else
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    //Decryption
    start = std::chrono::high_resolution_clock::now();
    decryptAES(iAESData, receivedData, oDecryptedData);
    end = std::chrono::high_resolution_clock::now();
    decryptionMicro = end - start;

    std::cout << "Verifying Time in microseconds: " << verifyingMicro.count() << std::endl << "Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
}

void clientSendEnvelope(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro;

    //Encrypting
    Data aEncryptedData;
    AESData aAESData;
    start = std::chrono::high_resolution_clock::now();
    envelope_seal(&publicKey, dataToSend, oEncryptedData, oAESData);
    end = std::chrono::high_resolution_clock::now();
    encryptionMicro = end - start;

    //Signing
    Data aSignatureData;
    start = std::chrono::high_resolution_clock::now();
    sign(privateKey, oEncryptedData, oSignatureData);
    end = std::chrono::high_resolution_clock::now();
    signingMicro = end - start;

    std::cout << "Encryption time in microseconds: " << encryptionMicro.count() << std::endl << "Signing time in microseconds: " << signingMicro.count() << std::endl;
}

void serverReceiveEnvelope(EVP_PKEY* publicKey, EVP_PKEY* privateKey, AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> verifyingMicro, decryptionMicro;

    //Verifying
    start = std::chrono::high_resolution_clock::now();
    bool verified = verify(publicKey, receivedData, signatureData);
    end = std::chrono::high_resolution_clock::now();
    verifyingMicro = end - start;

    if (verified)
        std::cout << "Signature VERIFIED!" << std::endl;
    else
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    //Decryption
    start = std::chrono::high_resolution_clock::now();
    envelope_open(privateKey, receivedData, oDecryptedData, iAESData);
    end = std::chrono::high_resolution_clock::now();
    decryptionMicro = end - start;

    std::cout << "Verifying Time in microseconds: " << verifyingMicro.count() << std::endl << "Decryption Time in microseconds: " << decryptionMicro.count() << std::endl;
}


int main(int argc, char* argv[]) {
    std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double,std::micro> encryptionMicro, signingMicro, verifyingMicro, decryptionMicro;
    int ret = -1;
    unsigned char key[keyLength];
    unsigned char initVector[EVP_MAX_IV_LENGTH];


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

    Data aToSend;
    memcpy(aToSend.data, toEncrypt.c_str(), toEncrypt.length());
    aToSend.length = toEncrypt.length();

    AESData aAESData;
    Data aSignatureData;
    Data aEncryptedData;
    Data aDecryptedData;

    std::cout << "------------------HomeMade version------------------" << std::endl;
    clientSendHomeMade(publicKey, privateKey, aAESData, aToSend, aEncryptedData, aSignatureData);
    serverReceiveHomeMade(publicKey, privateKey, aAESData, aSignatureData, aEncryptedData, aDecryptedData);

    std::string decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
    std::cout << "This after decryption: " << decryptedDataStr << std::endl;

    aEncryptedData.length = 0;
    aDecryptedData.length = 0;

    std::cout << "------------------Envelope version------------------" << std::endl;
    clientSendEnvelope(publicKey, privateKey, aAESData, aToSend, aEncryptedData, aSignatureData);
    serverReceiveEnvelope(publicKey, privateKey, aAESData, aSignatureData, aEncryptedData, aDecryptedData);

    decryptedDataStr = std::string((const char*)aDecryptedData.data).substr(0, aDecryptedData.length);
    std::cout << "This after decryption: " << decryptedDataStr << std::endl;
    EVP_PKEY_free(publicKey);
    EVP_PKEY_free(privateKey);

    return 0;
}

