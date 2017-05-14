#include "CryptoStructures.h"
#include "Signature.h"
#include "KeyManager.h"

namespace CryptoUtils {
class Envelope {
    private:
        static const int numOfAsymmetricKeypairs = 1;

        Signature _signature;
        KeyManager _keyMgr;

        void envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, EncryptedData& oEncryptedData, Data& oAESData);
        void envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData);
    public:
        void sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData);
        void receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData);
        void sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData);
        void receiveEnvelope(Data& iAESData, const EncryptedData& receivedData, Data& oDecryptedData);
};
}//namespace CryptoUtils
