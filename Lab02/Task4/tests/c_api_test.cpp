#include "aes_c_api.h"
#include <array>
#include <cstdio>

/* Kiểm tra thư viện động qua giao diện C, độc lập với test 18 vector. */
int main() {
    const std::array<uint8_t, 16> key{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const std::array<uint8_t, 16> input{0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const std::array<uint8_t, 16> expected{0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                           0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    std::array<uint8_t,16> cipher{}, back{};
    const int a = aes_encrypt_block(key.data(),16,input.data(),16,cipher.data(),16);
    const int b = aes_decrypt_block(key.data(),16,cipher.data(),16,back.data(),16);
    const bool pass = a==0 && b==0 && cipher==expected && back==input;
    std::puts(pass ? "C ABI Encrypt/Decrypt: PASS" : "C ABI Encrypt/Decrypt: FAIL");
    return pass ? 0 : 1;
}
