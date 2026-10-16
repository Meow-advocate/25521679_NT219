/*
 * Chức năng: Khai báo Key Wrap (KW) và Key Wrap with Padding (KWP) để bảo vệ khóa mật mã.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
#pragma once
#include "aes.hpp"
namespace nist {
common::Bytes kw_wrap(const AES&,const common::Bytes&);
common::Bytes kw_unwrap(const AES&,const common::Bytes&);
common::Bytes kwp_wrap(const AES&,const common::Bytes&);
common::Bytes kwp_unwrap(const AES&,const common::Bytes&);
}
