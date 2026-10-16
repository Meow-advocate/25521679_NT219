/*
 * Chức năng: Khai báo GCM và GMAC: kết hợp tạo keystream CTR với kiểm chứng tag dữ liệu.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
#pragma once
#include "aes.hpp"
namespace nist {
struct GcmResult {common::Bytes ciphertext;Block tag{};};
GcmResult gcm_encrypt(const AES&,const common::Bytes&,const common::Bytes&,const common::Bytes&);
common::Bytes gcm_decrypt(const AES&,const common::Bytes&,const common::Bytes&,const common::Bytes&,const Block&);
Block gmac(const AES&,const common::Bytes&,const common::Bytes&);
}
