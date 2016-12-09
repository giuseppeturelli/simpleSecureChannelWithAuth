#include <iostream>
#include "CryptoAES.h"

using namespace CryptoUtils;

int main(int argc, char* argv[]) {

    CryptoAES crypto;
    try {
    std::string toE(argv[1]);
    //std::string toE("All these momenwill be lost in time like tears in rainaaaaaaa");
    std::string encrStr = crypto.encryptAESString(toE);
    std::cout << "EncrSTR: " << encrStr << std::endl;
    std::string decrStr = crypto.decryptAESString(encrStr);
    std::cout << "DecrSTR: " << decrStr << std::endl;
    } catch(...) {
        std::cout << "Something went wrong" << std::endl;
    }

    return 0;
}
