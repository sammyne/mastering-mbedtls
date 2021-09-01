#include <iostream>
#include <string>

#include "mbedtls/cmac.h"

#include "ministd/ministd.h"

using namespace std;
using namespace ministd::encoding;

int main() {
  const string msg = "hello world";
  const uint8_t sk[16] = "how do you do";

  uint8_t MAC[16] = {0};

  auto cipher = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  if (auto err = mbedtls_cipher_cmac(cipher, sk, sizeof(sk) * 8, (const uint8_t*)msg.data(),
                                     msg.size(), MAC);
      0 != err) {
    return 1;
  }

  cout << "MAC = " << hex::EncodeToString(MAC, sizeof(MAC)) << endl;

  return 0;
}