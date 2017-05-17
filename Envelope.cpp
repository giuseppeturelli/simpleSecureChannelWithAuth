#include "Envelope.h"
#include <memory>

namespace CryptoUtils {
std::string Envelope::sendEnvelope(const std::string& strDataToSend) {
    //Deserialize Input
    PlaintextDataToSend dataInInput;
    dataInInput.ParseFromString(strDataToSend);

    //PlaintextDataInternal creation, let's roll
    PlaintextDataInternal dataToSend;

    //Fill PlaintextDataInternal with sender info, take your responsibility
    dataToSend.set_senderid(_keyMgr.getMyID());

    //Fill PlaintextDataInternal with receivers info
    for (int i=0; i<dataInInput.receiverid_size(); i++) {
        dataToSend.add_receiverid(dataInInput.receiverid(i));
    }

    //Fill PlaintextDataInternal with the data and optional params
    dataToSend.set_data(dataInInput.data());
    dataToSend.set_optionalparameters(dataInInput.optionalparameters());

    //TODO fill timestamp
    // dataToSend.set_timestamp(time.now());

    //Serialize input
    std::string serializedPlaintext;
    dataToSend.SerializeToString(&serializedPlaintext);

    int numOfReceivers = dataToSend.receiverid_size();

    if (numOfReceivers < 1 || numOfReceivers > 20) {
        CryptoException e("Disaster on the num of receivers");
        throw e;
    }

    EVP_PKEY* publicKeyList[20];
    unsigned char* aAESkeyList[20];

    for (int i=0; i<numOfReceivers; i++) {
        EVP_PKEY* aPubKey = _keyMgr.getEncryptionPublicKeyFor(dataToSend.receiverid(i));
        if (aPubKey != NULL) {
            publicKeyList[i] = aPubKey;
        }
        aAESkeyList[i] = new unsigned char[EVP_PKEY_size(aPubKey)];
    }

    //Preparing buffers for encryption
    //initVector tempbuffer
    unsigned char* tempBufferInitVector = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_256_cbc())];
    unsigned char* tempBufferEncryptedData = new unsigned char[serializedPlaintext.length() + EVP_MAX_BLOCK_LENGTH];

    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;
    int keyLength = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (!EVP_SealInit(ctx, EVP_aes_256_cbc(), aAESkeyList, &keyLength, tempBufferInitVector, publicKeyList, numOfReceivers))
        errorHandle();

    if (1 != EVP_SealUpdate(ctx, tempBufferEncryptedData, &partialLength, (unsigned char*) serializedPlaintext.data(), serializedPlaintext.length()))
        errorHandle();
    totLength = partialLength;

    if (1 != EVP_SealFinal(ctx, tempBufferEncryptedData + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;

    EVP_CIPHER_CTX_free(ctx);

    //Instantiate CryptoPayload object to hold all data that needs to be signed
    CryptoPayload encryptedPayload;
    encryptedPayload.set_version(0);

    //Add EncryptedKeys
    for (int i=0; i<numOfReceivers; i++) {
        //Add a EncryptedKey obj and preallocate a string of size EVP_PKEY_size(aPubKey)
        EncryptedKey* aEncryptedKey = encryptedPayload.add_keys();
        aEncryptedKey->set_receiverid(dataToSend.receiverid(i));
        aEncryptedKey->set_keydata(aAESkeyList[i], keyLength);
        delete[] aAESkeyList[i];
    }
    encryptedPayload.mutable_encrypteddata()->set_encrypteddata(tempBufferEncryptedData, totLength);
    encryptedPayload.mutable_encrypteddata()->set_initvector(tempBufferInitVector, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    delete[] tempBufferInitVector;

    std::string strDataEncrypted;
    encryptedPayload.SerializeToString(&strDataEncrypted);

    CryptoMessage message;
    std::string strSignatureData = _signature.sign(strDataEncrypted);
    message.set_signature(strSignatureData);
    message.set_payload(strDataEncrypted);

    delete[] tempBufferEncryptedData;

    std::string strToReturn;
    message.SerializeToString(&strToReturn);

    return strToReturn;
}

std::string Envelope::receiveEnvelope(const std::string& strReceivedData) {
    CryptoMessage message;
    message.ParseFromString(strReceivedData);

    CryptoPayload payload;
    payload.ParseFromString(message.payload());

    if (!_signature.verify(message.payload(), message.signature())) {
        CryptoException e("Disaster signature fails to verify");
        throw e;
    }


    int receivers = payload.keys_size();
    EncryptedKey* key;
    for (int i=0;i<receivers;i++) {
        key = payload.mutable_keys(i);
        if (key->receiverid().compare(_keyMgr.getMyID()) == 0) {
            break;
        }
    }

    unsigned char* tempBufferDecryptedData = new unsigned char[payload.encrypteddata().encrypteddata().length()];

    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), (unsigned char*) key->keydata().data(), key->keydata().length(), (unsigned char*) payload.encrypteddata().initvector().data(), _keyMgr.getEncryptionPrivateKey()))
       errorHandle();

    if (1 != EVP_OpenUpdate(ctx, tempBufferDecryptedData, &partialLength, (unsigned char*) payload.encrypteddata().encrypteddata().data(), payload.encrypteddata().encrypteddata().length()))
        errorHandle();

    totLength = partialLength;

    if (1 != EVP_OpenFinal(ctx, tempBufferDecryptedData + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;

    EVP_CIPHER_CTX_free(ctx);

    PlaintextDataInternal dataReceived;
    std::string strPTData((char*)tempBufferDecryptedData, totLength);
    dataReceived.ParseFromString(strPTData);

    delete[] tempBufferDecryptedData;

    PlaintextDataReceived toReturn;
    toReturn.set_senderid(dataReceived.senderid());
    toReturn.set_data(dataReceived.data());
    toReturn.set_additionalinfo(dataReceived.additionalinfo());

    std::string strToReturn;
    toReturn.SerializeToString(&strToReturn);
    return strToReturn;
}



/*
void Envelope::sendEnvelope(Data& oAESData, const Data& dataToSend, EncryptedData& oEncryptedData, Data& oSignatureData) {
    //Encrypting
    EVP_PKEY* publicKey = _keyMgr.getEncryptionPublicKeyFor(pubFile[0]);
    envelope_seal(publicKey, dataToSend, oEncryptedData, oAESData);

    //Signing
    _signature.sign(oEncryptedData.encryptedData, oSignatureData);
}

void Envelope::receiveEnvelope(Data& iAESData, const Data& signatureData, const EncryptedData& receivedData, Data& oDecryptedData) {
    //Verifying
    bool verified = _signature.verify(receivedData.encryptedData, signatureData);

    if (!verified)
        std::cout << "[NOT] Signature *not* VERIFIED! [NOT]" << std::endl;

    //Decryption
    envelope_open(receivedData, oDecryptedData, iAESData);
}

void Envelope::envelope_open(const EncryptedData& encryptedData, Data& oDecryptedData, const Data& iAESData) {
    EVP_CIPHER_CTX* ctx;
    int totLength = 0;
    int partialLength = 0;

    oDecryptedData.resize(encryptedData.encryptedData.size());

    if(!(ctx = EVP_CIPHER_CTX_new()))
        errorHandle();

    if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), iAESData.dataPtr(), iAESData.size(), encryptedData.initVector.dataPtr(), _keyMgr.getEncryptionPrivateKey()))
       errorHandle();


    if (1 != EVP_OpenUpdate(ctx, oDecryptedData.dataPtr(), &partialLength, encryptedData.encryptedData.dataPtr(), encryptedData.encryptedData.size()))
        errorHandle();

    totLength = partialLength;

    if (1 != EVP_OpenFinal(ctx, oDecryptedData.dataPtr() + totLength, &partialLength))
        errorHandle();

    totLength += partialLength;
    oDecryptedData.resize(totLength);

    EVP_CIPHER_CTX_free(ctx);
}
*/
}//namespace CryptoUtils
