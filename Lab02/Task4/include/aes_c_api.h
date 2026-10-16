/*
 * Giao diện ABI kiểu C dùng để gọi lõi AES C++ từ Python, Java và C#.
 * Các kiểu tham số được lựa chọn để tránh truyền trực tiếp đối tượng C++ qua ranh giới ngôn ngữ.
 */
#pragma once
#include <stdint.h>

/*
 * Giao diện C cho chương trình khác sử dụng thư viện AES C++.
 * Mã lỗi: 0 = thành công; -1 = con trỏ lỗi; -2 = khóa sai độ dài;
 * -3 = dữ liệu đầu vào không hợp lệ; -4 = vùng kết quả quá nhỏ;
 * -5 = lỗi xử lý nội bộ.
 * Hàm nhận mảng byte THẬT (không phải chuỗi ký tự HEX).
 */
#if defined(_WIN32)
  #if defined(AES_C_API_BUILD)
    #define AES_C_EXPORT __declspec(dllexport)
  #else
    #define AES_C_EXPORT __declspec(dllimport)
  #endif
#else
  #define AES_C_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
AES_C_EXPORT int aes_encrypt_block(const uint8_t* key, int key_len,
                                   const uint8_t* input, int input_len,
                                   uint8_t* output, int output_capacity);
AES_C_EXPORT int aes_decrypt_block(const uint8_t* key, int key_len,
                                   const uint8_t* input, int input_len,
                                   uint8_t* output, int output_capacity);
#ifdef __cplusplus
}
#endif
