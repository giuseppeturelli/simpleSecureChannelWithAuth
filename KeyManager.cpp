#include "KeyManager.h"
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/timeb.h>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <algorithm>

namespace CryptoUtils {
KeyManager::KeyManager() {
    loadKeys();
}

KeyManager::~KeyManager() {
    unloadKeys();
}

EVP_PKEY* KeyManager::getThePrivateKey() {
    return keys[privFile[0]];
}

EVP_PKEY* KeyManager::getPublicKeyFor(const std::string& keyName) {
    return keys[pubFile[0]];
}

void KeyManager::loadKeys() {

    auto it = privFile.begin();
    for (; it != privFile.end();++it) {
        loadPrivKey(*it);
    }
    it = pubFile.begin();
    for (; it != pubFile.end();++it) {
        loadPubKey(*it);
    }
}

void KeyManager::unloadKeys() {
    auto it = keys.begin();
    for (;it != keys.end();++it) {
        EVP_PKEY_free(it->second);
    }
}

void KeyManager::loadPubKey(std::string keyFilePath) {
    FILE* fp;
    EVP_PKEY* loadedKey = NULL;
    if ((fp = fopen(keyFilePath.c_str(), "r")) != NULL) {
        loadedKey = PEM_read_PUBKEY(fp, NULL, 0, NULL);
        if (loadedKey == NULL)
            std::cout << "Failed to load key!" << std::endl;
        fclose(fp);
        keys[keyFilePath] = loadedKey;
    } else {
        std::cout << "PubKey missing!" << std::endl;
    }
}

void KeyManager::loadPrivKey(std::string keyFilePath) {
    FILE* fp;
    EVP_PKEY* loadedKey = NULL;
    if ((fp = fopen(keyFilePath.c_str(), "r")) != NULL) {
        loadedKey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
        if (loadedKey == NULL)
            std::cout << "Failed to load key!" << std::endl;
        fclose(fp);
        keys[keyFilePath] = loadedKey;
    } else {
        std::cout << "PrivKey missing!" << std::endl;
    }
}

void KeyManager::generateRandomBuffer(unsigned char* ioRandBuffer, int size) {
    RAND_bytes(ioRandBuffer, size);
}

}//namespace CryptoUtils
