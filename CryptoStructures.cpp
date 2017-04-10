#include "CryptoStructures.h"

namespace CryptoUtils {

    Data::Data() {};
    Data::Data(int size) { data_.resize(size); }
    
    unsigned char* Data::dataPtr() { return &data_[0]; }
    const unsigned char* Data::dataPtr() const { return &data_[0]; }
    void Data::resize(int size) { data_.resize(size); }
    int Data::size() { return data_.size(); }
    const int Data::size() const { return data_.size(); }
    bool Data::equal(const Data& toCompare) { return std::equal(data_.begin(), data_.end(), toCompare.data_.begin()); }


    void errorHandle() {
        char error[1024];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), error, 1024);
        std::cout << "Error value: " << error << std::endl;
        throw 1;
    }
}//namespace CryptoUtils
