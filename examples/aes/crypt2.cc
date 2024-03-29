#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "ministd/ministd.h"

#include "mbedtls/config.h"

#include "mbedtls/aes.h"

using namespace std;

using namespace ministd::encoding;

using defer = shared_ptr<void>;
using Bytes = vector<uint8_t>;

Bytes Pad(const string msg);

int main() {
  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init(&aes_ctx);
  defer _1(nullptr, [&](...) { mbedtls_aes_free(&aes_ctx); });

  const int KEY_LEN = 32;
  uint8_t key[KEY_LEN] = "mbedtls-key";
  cout << "key = " << hex::EncodeToString(key, KEY_LEN) << endl;

  {
    auto status = mbedtls_aes_setkey_enc(&aes_ctx, key, 256);
    if (0 != status) {
      cout << "failed to set key" << endl;
      return status;
    }
  }

  const int IV_LEN = 16;
  uint8_t iv[IV_LEN] = "mbedtls-iv";
  cout << "iv = " << hex::EncodeToString(iv, IV_LEN) << endl;

  auto msg = Pad("Hello World");
  cout << "msg = " << hex::EncodeToString(msg.data(), msg.size()) << endl;

  vector<uint8_t> ciphertext(msg.size());

  // encrypt
  {
    uint8_t iv_[IV_LEN];
    memcpy(iv_, iv, IV_LEN);  // copy to avoid change by encrypt

    auto status = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, msg.size(), iv_, msg.data(),
                                        ciphertext.data());
    if (0 != status) {
      cout << "failed to encrypt: " << status << endl;
      return status;
    }

    cout << "ciphertext = " << hex::EncodeToString(ciphertext.data(), ciphertext.size()) << endl;
  }

  {
    auto status = mbedtls_aes_setkey_dec(&aes_ctx, key, 256);
    if (0 != status) {
      cout << "failed to set decryption key" << endl;
      return status;
    }
  }

  // decrypt
  {
    vector<uint8_t> recovered(ciphertext.size());

    uint8_t iv_[IV_LEN];
    memcpy(iv_, iv, IV_LEN);

    auto status = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, ciphertext.size(), iv_,
                                        ciphertext.data(), recovered.data());
    if (0 != status) {
      cout << "failed to decrypt: " << status << endl;
      return status;
    }

    auto v1 = hex::EncodeToString(msg.data(), msg.size());
    auto v2 = hex::EncodeToString(recovered.data(), recovered.size());
    if (v1 != v2) {
      cout << "failed to decrypt ciphertext: got " << v2 << ", expect " << v1 << endl;
    } else {
      cout << "decryption ok, got " << v2 << endl;
    }
  }

  return 0;
}

Bytes Pad(const string msg) {
  auto ell = (msg.length() + 15) / 16 * 16;

  Bytes out(ell, 0);
  memcpy(out.data(), msg.data(), msg.length());

  return out;
}