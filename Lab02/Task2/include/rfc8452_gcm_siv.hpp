#pragma once
#include "aes.hpp"
namespace nist {
struct SivResult {common::Bytes ciphertext;Block tag{};};
SivResult gcm_siv_encrypt(const common::Bytes&,const common::Bytes&,const common::Bytes&,const common::Bytes&);
common::Bytes gcm_siv_decrypt(const common::Bytes&,const common::Bytes&,const common::Bytes&,const common::Bytes&,const Block&);
}
