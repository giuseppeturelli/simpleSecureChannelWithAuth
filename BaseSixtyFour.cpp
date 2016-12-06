#include "BaseSixtyFour.h"

namespace CryptoUtils {

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

BaseSixtyFour::BaseSixtyFour() {}

BaseSixtyFour::~BaseSixtyFour() {}

void BaseSixtyFour::encodeblock (unsigned char in[3], unsigned char out[4], int len) {
    out[0] = cb64[in[0] >> 2];
    out[1] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
    out[2] = (unsigned char) (len > 1 ? cb64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[in[2] & 0x3f] : '=');
}

void BaseSixtyFour::decodeblock (unsigned char in[4], unsigned char out[3]) {
    out[0] = (unsigned char) (in[0] << 2 | in[1] >> 4);
    out[1] = (unsigned char) (in[1] << 4 | in[2] >> 2);
    out[2] = (unsigned char) (((in[2] << 6) & 0xc0) | in[3]);
}

void BaseSixtyFour::decodeBase64 (const char *infile, size_t inLength, char *outfile, size_t *oLength) {
    unsigned char in[4], out[3], v;
    size_t i, len;
    *oLength = 0;
    //loop on all characters on input
    for (size_t aCurrent = 0 ; aCurrent < inLength;) {
        for(len = 0, i = 0; i < 4 && aCurrent <= inLength; ++i) {
            v = 0;
            while(aCurrent <= inLength && v == 0) {
                if (aCurrent == inLength) {
                    v = 0;
                }
                else {
                    v =  infile[aCurrent];
                }
                ++aCurrent;
                // strip useless characters (noise, not part of the
                // base64, such as blank, EOF, etc)
                v =  ((v < 43 || v > 122) ? 0 : cd64[v - 43]);
                if(v) {
                    v =  ((v == '$') ? 0 : v - 61);
                }
            }
            if(aCurrent <= inLength) {
                ++len;
                if(v) {
                    in[i] =  v - 1;
                }
            }
            else {
                in[i] = 0;
            }

        }
        if(len) {
            decodeblock(in, out);
            for(i = 0; i < len - 1; ++i) {
                outfile[*oLength] =  out[i];
                ++(*oLength);
            }
        }
    }
}

void BaseSixtyFour::encodeBase64 (const char *infile, size_t inLength, char *outfile, size_t *oLength) {
    unsigned char in[3], out[4];
    int i, len = 0;
    size_t aCurrent = 0;
    *oLength = 0;
    while(aCurrent < inLength) {
        len = 0;
        for(i = 0; i < 3; i++) {
            if(aCurrent < inLength) {
                len++;
                in[i] = infile[aCurrent];
            }
            else {
                in[i] = 0;
            }
            ++aCurrent;
        }
        if(len) {
            encodeblock(in, out, len);
            for(i = 0; i < 4; i++) {
                outfile[*oLength] =out[i];
                ++(*oLength);
            }
        }
    }
}

size_t BaseSixtyFour::bin2Base64Length (size_t iBinaryLength) {
    size_t aQuotient = iBinaryLength / 3;
    size_t result = aQuotient * 4;
    size_t aRemainder = iBinaryLength % 3;
    if (aRemainder != 0){
        result +=4;
    }
    return result;
}

void BaseSixtyFour::decodeBase64FromStringToChar(std::string data, char* outfile, size_t* oLength) {
    this->decodeBase64(data.c_str(), data.length(), outfile, oLength);
}

std::string BaseSixtyFour::decodeBase64FromStringToString(std::string data) {
    char* outputTemp = new char[data.length()];
    size_t oLength = 0;

    this->decodeBase64FromStringToChar(data, outputTemp, &oLength);

    std::string retStr = std::string(outputTemp).substr(0,oLength);
    delete[] outputTemp;
    return retStr;
}

std::string BaseSixtyFour::encodeBase64FromStringToString(std::string data) {
    return this->encodeBase64FromCharToString(data.c_str(), data.length());
}

std::string BaseSixtyFour::encodeBase64FromCharToString(const char* infile, const size_t iLength) {
    char* outputTemp = new char[2*iLength];
    size_t oLength = 0;

    this->encodeBase64(infile, iLength, outputTemp, &oLength);

    std::string retStr = std::string(outputTemp).substr(0,oLength);
    delete [] outputTemp;
    return retStr;
}
}//namespace CryptoUtils
