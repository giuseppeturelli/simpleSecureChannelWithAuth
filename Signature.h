#include "BaseSixtyFour.h"
#include "CryptoStructures.h"
#include "KeyManager.h"
#include <openssl/evp.h>

namespace CryptoUtils {
class Signature {
    public:
        void sign(const Data& toSign, Data& oSignatureData);
        bool verify(const Data& signedData, const Data& signatureData);
    private:

        KeyManager _keyMgr;
};
}//namespace CryptoUtils

