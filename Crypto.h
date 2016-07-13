#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>
#include <vector>
#include <numeric>

static const int bufferLength = 2048;
static const int keyLength = 1024;

static std::vector<float> signTime, encryptTime, decryptTime, verifyTime;
static int messagesReceived = 0;

static const std::vector<std::string> privFile = {"./rsaKey1024", "./rsaKey2048", "./rsaKey4096" };
static const std::vector<std::string> pubFile = {"./rsaKey1024_pub", "./rsaKey2048_pub", "./rsaKey4096_pub"};

//static const std::string toEncrypt = "AllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainxAllTheseMomentsWillBeLostInTimeLikeTearsInRainx++";
static const std::string toEncrypt = "u8bZgY4IB0CHtAxNTLpa8oCWji8kvAqFx07Mb3sptkBC9RPS3kOe3w4xVFvv77Go01LG2yXzk300yTTJxNNRzv5BDt2LeWcbqhKgIJli1gjlpgy2yeueLaTrkOBMPKIWq1GNyv3E3k5u8kkQUzDumrUUvu6XZvBstOlWKcni2k3lHD382yaDhwvvPau8Acz7Uucaeg1hTr3G0VB2ESSVssAwzbGgS5OUfA24U2ifSOe4IncxWB8WJF9NXbytoM7gSbF2M20iPRUhtqnTDi4oQxDEUUiySCjKRh2kUNQ6Qv4tAfiMbtei6fOrxF6Ivb6oCCY0E2m2OuIOTPVrvVt0s8x2u6oiElyIwjG7oa70TvLEaFRs6rRRNznHf7WyvTeCn0xCPQwYCWXHzaAnDbNIoQv6XlWkNwry1AZRkESvXg8zqkmCYgY8STBZC1nk5El8yGCFUvSnUM4tDgMUh0cUQDiwcRjzHM5b4ZnvTLcLrZ5g5J8PrHe4zPxquj0BCHD3ghUb0oxSqLALTI0qmfGtXuQ9yiAVL8Pq4lY7aSlvfcP2z5V9xTPOsgb5p6hNEGrj8BfswkXrva5pZ6YmD0nvv6GJhDLC0lbW20XWmVr9RR1XkHXUTmZx7DGvrKoG8SOJnKuYWEoHstqNr11LvowKPuKNEzKN4Octy8kH9yFu3Y007qz5cINSXuJajuuUHcVnK1z45cUikeSwbffBVr2tugmEsMbgZKuNTMgzpu2juK0AQ7Y0N4CNgaXTv96vR0Kr2iBeMGnGlBQ8tSjf6cizPbGQrLkRs96VR8Xp6r3b0i08ywapEAPv38eQHWvu093JZcUTpmp13VzeJK9mvphaYWQmaFJU9i8qkRrI5crFItCh0Z4BSEkvlJwwFMhtQv78AzDjWzfbxDaVS1XSk2p5REDS3PmGx9vQts7W90rJuSxsEiLbNS4hNjKx1YeuvCinoTkhwcAEqx4gpBJT7ucRaNHooOK7eEPM03WzSUne2efWfK6MQrNhXD78N9elDYww";

struct Data {
    unsigned char data[bufferLength];
    long unsigned int length = 0;

    template <typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & data;
        ar & length;
    }
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[bufferLength];
    int length = 0;

    template <typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & key;
        ar & initVector;
        ar & length;
    }
};

//Helper Functions
void printAverage();
//Getting RSA keypair


class CryptoCollection {
    public:
        ~CryptoCollection();

        void setPrivateKey(const std::string& keyFilePath);
        void setPublicKey(const std::string& keyFilePath);

        void encryptAES(const AESData& iAESData, const Data& toEncrypt, Data& oEncryptedData);
        void decryptAES(const AESData& iAESData, const Data& toDecrypt, Data& oDecryptedData);

        void sign(const Data& toSign, Data& oSignatureData);
        bool verify(const Data& signedData, const Data& signatureData);

        void encryptRSA(const Data& toEncrypt, Data& oEncryptedData);
        void decryptRSA(const Data& toDecrypt, Data& oDecryptedData);

        void sendHomeMade(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);
        void receiveHomeMade(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);

        void sendEnvelope(AESData& oAESData, const Data& dataToSend, Data& oEncryptedData, Data& oSignatureData);
        void receiveEnvelope(AESData& iAESData, const Data& signatureData, const Data& receivedData, Data& oDecryptedData);
    private:
        void generateRandomBuffer(unsigned char ioRandBuffer[], int size);
        void errorHandle();

        void envelope_seal(EVP_PKEY** publicKey, const Data& toEncrypt, Data& oEncryptedData, AESData& oAESData);
        void envelope_open(const Data& encryptedData, Data& oDecryptedData, const AESData& iAESData);

        EVP_PKEY* privateKey;
        EVP_PKEY* publicKey;
};
