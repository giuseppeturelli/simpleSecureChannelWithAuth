#include <iostream>
#include "Crypto.h"

using namespace CryptoUtils;

int main(int argc, char* argv[]) {

    CryptoCollection crypto;
    std::string toE(argv[1]);
    //std::string toE("All these momenwill be lost in time like tears in rainaaaaaaa");
    std::string encrStr = crypto.encryptAESString(toE);
    std::cout << "EncrSTR: " << encrStr << std::endl;

    std::string decrStr = crypto.decryptAESString(encrStr);
    std::cout << "DecrSTR: " << decrStr << std::endl;

    return 0;
}
