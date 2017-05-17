#include "BaseSixtyFour.h"
#include "CryptoStructures.h"
#include "KeyManager.h"
#include <openssl/evp.h>

namespace CryptoUtils {
class Signature {
    public:
        std::string sign(const std::string& toSign);
        bool verify(const std::string& signedData, const std::string& signatureData);
    private:

        KeyManager _keyMgr;
};
}//namespace CryptoUtils
