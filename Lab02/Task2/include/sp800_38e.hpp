/*
 * Chức năng: Khai báo XTS phục vụ mã hóa đơn vị dữ liệu với hai khóa và tweak.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
#pragma once
#include "aes.hpp"
namespace nist {
common::Bytes xts_encrypt(const common::Bytes&,const common::Bytes&,const Block&);
common::Bytes xts_decrypt(const common::Bytes&,const common::Bytes&,const Block&);
}
