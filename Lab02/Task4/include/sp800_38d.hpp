#pragma once
#include "aes.hpp"
namespace nist {
struct GcmResult {common::Bytes ciphertext;Block tag{};};
GcmResult gcm_encrypt(const AES&,const common::Bytes&,const common::Bytes&,const common::Bytes&);
common::Bytes gcm_decrypt(const AES&,const common::Bytes&,const common::Bytes&,const common::Bytes&,const Block&);
Block gmac(const AES&,const common::Bytes&,const common::Bytes&);
}
