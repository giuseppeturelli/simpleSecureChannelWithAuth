static const int bufferLength = 2048;
static const int keyLength = 1024;

struct Data {
    unsigned char data[bufferLength];
    long unsigned int length = 0;
};

struct AESData {
    unsigned char key[keyLength];
    unsigned char initVector[bufferLength];
    int length = 0;
};
