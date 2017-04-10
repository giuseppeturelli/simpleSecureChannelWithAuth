#include "CryptoStructures.h"
#include "Signature.h"

namespace CryptoUtils {
class Envelope {
    private:
        static const int numOfAsymmetricKeypairs = 1;
        EVP_PKEY* publicKey;
        EVP_PKEY* privateKey;

        Signature _signature;

    public:
        void sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData);
        void receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData);
        void sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData);
        void receiveEnvelope(Data& iAESData, const EncryptedData& receivedData, Data& oDecryptedData);
        void envelope_seal(EVP_PKEY* publicKey, const Data& toEncrypt, EncryptedData& oEncryptedData, Data& oAESData);
        void envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData);
};
}//namespace CryptoUtils
