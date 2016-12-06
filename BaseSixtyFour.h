#ifndef BASESIXTYFOUR_H
#define BASESIXTYFOUR_H
#include <stdlib.h>
#include <string>

namespace CryptoUtils {

class BaseSixtyFour {
    public:
    BaseSixtyFour();
    ~BaseSixtyFour();

    size_t bin2Base64Length(size_t iBinaryLength);

    void decodeBase64FromStringToChar(std::string data, char *outfile, size_t *oLength);
    std::string decodeBase64FromStringToString(std::string data);

    std::string encodeBase64FromCharToString(const char *infile, const size_t iLength);
    std::string encodeBase64FromStringToString(std::string data);

    private:
    BaseSixtyFour(const BaseSixtyFour &right);
    BaseSixtyFour & operator=(const BaseSixtyFour &right);

    void encodeblock(unsigned char in[3], unsigned char out[4], int len);
    void decodeblock(unsigned char in[4], unsigned char out[3]);

    void decodeBase64(const char *infile, size_t inLength, char *outfile, size_t *oLength);
    void encodeBase64(const char *infile, size_t inLength, char *outfile, size_t *oLength);
};
}//namespace CryptoUtils
#endif
