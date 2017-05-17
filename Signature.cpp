#include "Signature.h"

namespace CryptoUtils {

std::string Signature::sign(const std::string& toSign) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, _keyMgr.getSignaturePrivateKey()))
        errorHandle();

    if (1 != EVP_DigestSignUpdate(digestSignCtx, toSign.data(), toSign.size()))
        errorHandle();

    //Size discovery
    int foreseenLength = 0;
    if (1 != EVP_DigestSignFinal(digestSignCtx, NULL, (size_t*) &foreseenLength))
        errorHandle();

    unsigned char* tempSignedData = new unsigned char[foreseenLength];

    int finalLength = foreseenLength;
    if (1 != EVP_DigestSignFinal(digestSignCtx, tempSignedData, (size_t*) &finalLength))
        errorHandle();
    SignatureData signedData;
    signedData.set_senderid(_keyMgr.getMyID());
    signedData.set_signaturedata(tempSignedData, finalLength);

    delete[] tempSignedData;

    EVP_MD_CTX_destroy(digestSignCtx);
    //END: Message Signing operation

    std::string strToReturn;
    signedData.SerializeToString(&strToReturn);
    return strToReturn;
}

bool Signature::verify(const std::string& signedData, const std::string& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, _keyMgr.getSignaturePublicKeyFor(pubFile[0])))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.data(), signedData.size()))
        return false;

    bool ret = EVP_DigestVerifyFinal(digestSignCtx, (unsigned char*) signatureData.data(), signatureData.size());

    EVP_MD_CTX_destroy(digestSignCtx);

    return ret;
    //END: Message Verifying operation
}
}
