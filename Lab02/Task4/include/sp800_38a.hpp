#pragma once
#include "aes.hpp"
namespace nist {
using Bytes=common::Bytes;
Bytes ecb_encrypt(const AES&, Bytes, bool pad=true);
Bytes ecb_decrypt(const AES&,const Bytes&,bool unpad=true);
Bytes cbc_encrypt(const AES&,Bytes,const Bytes&,bool pad=true);
Bytes cbc_decrypt(const AES&,const Bytes&,const Bytes&,bool unpad=true);
Bytes cfb128_encrypt(const AES&,const Bytes&,const Bytes&);
Bytes cfb128_decrypt(const AES&,const Bytes&,const Bytes&);
Bytes cfb8_encrypt(const AES&,const Bytes&,const Bytes&);
Bytes cfb8_decrypt(const AES&,const Bytes&,const Bytes&);
Bytes ofb_transform(const AES&,const Bytes&,const Bytes&);
Bytes ctr_transform(const AES&,const Bytes&,const Bytes&);
}
