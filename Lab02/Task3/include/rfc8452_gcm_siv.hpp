/*
 * Chức năng: Khai báo cấu trúc chứa bản mã và tag của AES-GCM-SIV; tách phần giao diện khỏi phần tính POLYVAL và CTR.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
#pragma once
#include "aes.hpp"
namespace nist {
struct SivResult {common::Bytes ciphertext;Block tag{};};
SivResult gcm_siv_encrypt(const common::Bytes&,const common::Bytes&,const common::Bytes&,const common::Bytes&);
common::Bytes gcm_siv_decrypt(const common::Bytes&,const common::Bytes&,const common::Bytes&,const common::Bytes&,const Block&);
}
