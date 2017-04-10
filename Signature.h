#include "BaseSixtyFour.h"
#include "Structures.h"
#include <openssl/evp.h>

namespace CryptoUtils {
class Signature {
    public:
        void sign(const Data& toSign, Data& oSignatureData);
        bool verify(const Data& signedData, const Data& signatureData);
    private:
        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
};
}//namespace CryptoUtils

