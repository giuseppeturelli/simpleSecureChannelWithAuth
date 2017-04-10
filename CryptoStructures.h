#include <vector>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace CryptoUtils {

class Data {
    private:
        std::vector<unsigned char> data_;
    public:
        Data() {}
        Data(int size) { data_.resize(size); }

        unsigned char* dataPtr() { return &data_[0]; }
        const unsigned char* dataPtr() const { return &data_[0]; }
        void resize(int size) { data_.resize(size); }
        int size(){ return data_.size(); }
        const int size() const { return data_.size(); }
        bool equal(const Data& toCompare) { return std::equal(data_.begin(), data_.end(), toCompare.data_.begin()); }

};

class EncryptedData {
    public:
        Data encryptedData;
        Data initVector;
};
void errorHandle() {
    char error[1024];
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), error, 1024);
    std::cout << "Error value: " << error << std::endl;
    throw 1;
}
}//namespace CryptoUtils

