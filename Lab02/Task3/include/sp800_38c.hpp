#pragma once
#include "aes.hpp"
namespace nist {
struct CcmResult { common::Bytes ciphertext; common::Bytes tag; };
CcmResult ccm_encrypt(const AES&, const common::Bytes&, const common::Bytes&,const common::Bytes&,int taglen=8);
common::Bytes ccm_decrypt(const AES&,const common::Bytes&,const common::Bytes&,const common::Bytes&,const common::Bytes&);
}
