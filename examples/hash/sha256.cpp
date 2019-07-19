#include <iostream>

#include "mbedtls/config.h"
#include "mbedtls/sha256.h"

#include "cppcodec/hex_default_lower.hpp"

using namespace std;

using hex = cppcodec::hex_lower;

int main()
{
    const string msg = "Hello World";

    uint8_t md[32];
    auto status = mbedtls_sha256_ret((const uint8_t *)(msg.data()), msg.length(), md, 0);
    if (0 != status)
    {
        cout << "failed " << status << endl;
        return status;
    }

    cout << "digest = " << hex::encode(md, sizeof(md)) << endl;

    return 0;
}