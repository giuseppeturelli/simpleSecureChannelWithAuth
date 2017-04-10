#include "Signature.h"

namespace CryptoUtils {

void Signature::sign(const Data& toSign, Data& oSignatureData) {
    //START: Message Signing operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();

    if (1 != EVP_DigestSignInit(digestSignCtx, NULL, EVP_sha256(), NULL, _keyMgr.getThePrivateKey()))
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

bool Signature::verify(const Data& signedData, const Data& signatureData) {
    //START: Message Verifying operation
    EVP_MD_CTX* digestSignCtx = EVP_MD_CTX_create();
    if (1 != EVP_DigestVerifyInit(digestSignCtx, NULL, EVP_sha256(), NULL, _keyMgr.getPublicKeyFor(pubFile[0])))
        errorHandle();

    if (1 != EVP_DigestVerifyUpdate(digestSignCtx, signedData.dataPtr(), signedData.size()))
        return false;

    bool ret = EVP_DigestVerifyFinal(digestSignCtx, (unsigned char*) signatureData.dataPtr(), signatureData.size());

    EVP_MD_CTX_destroy(digestSignCtx);

    return ret;
    //END: Message Verifying operation
}
}
