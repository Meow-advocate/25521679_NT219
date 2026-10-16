/*
 * Chức năng: Khai báo ECB, CBC, CFB8, CFB128, OFB, CTR. Các hàm dùng chung lõi AES ở aes.hpp và nhận dữ liệu dạng dãy byte.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
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
