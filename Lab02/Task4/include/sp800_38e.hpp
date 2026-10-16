#pragma once
#include "aes.hpp"
namespace nist {
common::Bytes xts_encrypt(const common::Bytes&,const common::Bytes&,const Block&);
common::Bytes xts_decrypt(const common::Bytes&,const common::Bytes&,const Block&);
}
