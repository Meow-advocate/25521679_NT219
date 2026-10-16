/*
 * Chức năng: Khai báo hàm CMAC: tạo mã xác thực thông điệp, không trả về ciphertext.
 * File này khai báo giao diện; phần triển khai tương ứng nằm trong thư mục src/.
 */
#pragma once
#include "aes.hpp"
namespace nist { Block cmac(const AES&,const common::Bytes&); }
