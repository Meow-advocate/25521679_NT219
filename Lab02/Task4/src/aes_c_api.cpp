#include "aes_c_api.h"
#include "aes.hpp"
#include <algorithm>
#include <vector>

/*
 * Hàm dùng chung cho mã hóa và giải mã một block AES.
 * Kiểm tra kích thước trước khi đưa dữ liệu vào class AES của Task 1.
 * Bắt mọi exception để không có lỗi C++ vượt qua biên giới C ABI.
 */
static int process_block(const uint8_t* key, int key_len,
                         const uint8_t* input, int input_len,
                         uint8_t* output, int output_capacity,
                         bool decrypt) noexcept {
    if (!key || !input || !output) return -1;
    if (key_len != 16 && key_len != 24 && key_len != 32) return -2;
    if (input_len != 16) return -3;
    if (output_capacity < 16) return -4;
    try {
        std::vector<Byte> key_data(key, key + key_len);
        Block block{};
        std::copy(input, input + 16, block.begin());
        AES aes(key_data);
        Block result = decrypt ? aes.decrypt(block) : aes.encrypt(block);
        std::copy(result.begin(), result.end(), output);
        return 0;
    } catch (...) {
        return -5;
    }
}

/* Hai hàm tên cố định cho Python, Java bridge và C# gọi từ DLL/SO. */
extern "C" int aes_encrypt_block(const uint8_t* key, int key_len,
                                   const uint8_t* input, int input_len,
                                   uint8_t* output, int output_capacity) {
    return process_block(key, key_len, input, input_len, output, output_capacity, false);
}
extern "C" int aes_decrypt_block(const uint8_t* key, int key_len,
                                   const uint8_t* input, int input_len,
                                   uint8_t* output, int output_capacity) {
    return process_block(key, key_len, input, input_len, output, output_capacity, true);
}
