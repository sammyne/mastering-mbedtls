#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "mbedtls/config.h"
#include "mbedtls/cipher.h"

#include "ministd/ministd.h"

using namespace std;
using namespace ministd::encoding;

using defer = shared_ptr<void>;

vector<uint8_t> pad(const string msg) {
  auto ell = (msg.length() + 15) / 16 * 16;

  vector<uint8_t> out(ell, 0);
  memcpy(out.data(), msg.data(), msg.length());

  return out;
}

int main() {
  mbedtls_cipher_context_t ctx;

  mbedtls_cipher_init(&ctx);
  defer _1(nullptr, [&](...) { mbedtls_cipher_free(&ctx); });

  auto info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, 256, MBEDTLS_MODE_CBC);
  {
    auto status = mbedtls_cipher_setup(&ctx, info);
    if (0 != status) {
      cout << "[SETUP] failed: " << status << endl;
      return status;
    }
  }

  const int KEY_LEN = 32;
  uint8_t key[KEY_LEN] = "mbedtls-key";
  cout << "key = " << hex::EncodeToString(key, KEY_LEN) << endl;

  const int IV_LEN = 16;
  uint8_t iv[IV_LEN] = "mbedtls-iv";
  cout << "iv = " << hex::EncodeToString(iv, IV_LEN) << endl;

  auto msg = pad("Hello World");
  cout << "msg = " << hex::EncodeToString(msg.data(), msg.size()) << endl;

  vector<uint8_t> ciphertext(msg.size());

  // encrypt
  {
    auto status = mbedtls_cipher_setkey(&ctx, key, info->key_bitlen, MBEDTLS_ENCRYPT);
    if (0 != status) {
      cout << "[ENCRYPTION] failed to set key: " << status << endl;
      return status;
    }

    status = mbedtls_cipher_set_iv(&ctx, iv, IV_LEN);
    if (0 != status) {
      cout << "[ENCRYPTION] failed to set iv" << endl;
      return status;
    }

    size_t out_len;
    status = mbedtls_cipher_update(&ctx, msg.data(), msg.size(), ciphertext.data(), &out_len);
    if (0 != status) {
      cout << "failed to encrypt: " << status << endl;
      return status;
    }

    // cout << "[ENCRYPTION] ciphertext = " << hex::EncodeToString(ciphertext) << endl;
    // cout << "[ENCRYPTION] ciphertext length = " << out_len << endl;

    uint8_t out[32];
    status = mbedtls_cipher_finish(&ctx, out, &out_len);
    if (0 != status) {
      cout << "[ENCRYPTION] finish" << status << endl;
      return status;
    }
    // cout << "[ENCRYPTION] out_len = " << out_len << endl;
    // cout << "[ENCRYPTION] out = " << hex::EncodeToString(out, out_len) << endl;

    // ciphertext.resize(ciphertext.size() + out_len);
    for (size_t i = 0; i < out_len; i++) {
      ciphertext.emplace_back(out[i]);
    }

    cout << "[ENCRYPTION] ciphertext = "
         << hex::EncodeToString(ciphertext.data(), ciphertext.size()) << endl;
    cout << "[ENCRYPTION] ciphertext length = " << ciphertext.size() << endl;
  }

  {
    auto status = mbedtls_cipher_reset(&ctx);
    if (0 != status) {
      cout << "[RESET] failed: " << status << endl;
      return status;
    }

    status = mbedtls_cipher_setup(&ctx, info);
    if (0 != status) {
      cout << "[SETUP] failed: " << status << endl;
      return status;
    }
  }

  // decrypt
  {
    auto status = mbedtls_cipher_setkey(&ctx, key, info->key_bitlen, MBEDTLS_DECRYPT);
    if (0 != status) {
      cout << "[DECRYPTION] failed to set key" << endl;
      return status;
    }

    status = mbedtls_cipher_set_iv(&ctx, iv, IV_LEN);
    if (0 != status) {
      cout << "[DECRYPTION] failed to set iv" << endl;
      return status;
    }

    vector<uint8_t> recovered(ciphertext.size());
    size_t out_len;

    status = mbedtls_cipher_update(&ctx, ciphertext.data(), ciphertext.size(), recovered.data(),
                                   &out_len);
    if (0 != status) {
      cout << "[DECRYPTION] failed to update: " << status << endl;
      return status;
    }

    cout << "[DECRYPTION] recovered = " << hex::EncodeToString(recovered.data(), recovered.size())
         << endl;
    cout << "[DECRYPTION] recovered length = " << recovered.size() << endl;

    uint8_t out[32];
    status = mbedtls_cipher_finish(&ctx, out, &out_len);
    if (0 != status) {
      cout << "[DECRYPTION] finish failed: " << status << endl;
      return status;
    }
    // cout << "[DECRYPTION] out_len = " << out_len << endl;

    auto v1 = hex::EncodeToString(msg.data(), msg.size());
    auto v2 = hex::EncodeToString(recovered.data(), msg.size());
    if (v1 != v2) {
      cout << "failed to decrypt ciphertext: got " << v2 << ", expect " << v1 << endl;
    } else {
      cout << "decryption ok, got " << v2 << endl;
    }
  }

  return 0;
}