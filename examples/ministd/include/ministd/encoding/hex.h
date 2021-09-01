#pragma once

#include <string>
#include <cstdint>

namespace ministd::encoding::hex {

std::string EncodeToString(const uint8_t *data, size_t dataLen);

}
