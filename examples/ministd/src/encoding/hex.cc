#include "ministd/encoding/hex.h"

namespace ministd::encoding::hex {

using std::string;

string EncodeToString(const uint8_t *data, size_t dataLen) {
  const char *ALPHABET = "0123456789ABCDEF";
  string out;
  out.reserve(dataLen);

  for (auto i = 0; i < dataLen; ++i) {
    out.push_back(ALPHABET[data[i] >> 4]);
    out.push_back(ALPHABET[data[i] & 0x0f]);
  }

  return out;
}

}  // namespace ministd::encoding::hex
