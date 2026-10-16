#include "sp800_38d.hpp"
#include <algorithm>
namespace nist {
using Bytes = common::Bytes;


// GCM = CTR (mã hóa dữ liệu) + GHASH (xác thực ciphertext và AAD).
// Ví dụ minh họa chỉ dùng nonce 12 byte và tag 16 byte đúng quy tắc chuẩn.
// Nonce KHÔNG được tái sử dụng với cùng key. Người gọi phải cung cấp nonce.

// GHASH làm phép nhân trong GF(2^128) (khác với gmul GF(2^8) của AES).
// Duyệt từng bit của X từ trái sang phải, cộng bằng XOR.
// Khi dịch V sang phải một bit mà bit cuối trước khi dịch bằng 1,
// XOR byte đầu với 0xE1 (đa thức rút gọn của GCM).
Block gf128_mul(const Block& x, const Block& y) {
    Block z{};
    Block v = y;
    for (int bit = 0; bit < 128; ++bit) {
        if ((x[bit / 8] >> (7 - bit % 8)) & 1) {
            for (int j = 0; j < 16; ++j) z[j] ^= v[j];
        }
        bool last_bit = (v[15] & 1) != 0;
        for (int j = 15; j >= 0; --j) {
            Byte previous = (j == 0) ? 0 : v[j - 1];
            v[j] = static_cast<Byte>((v[j] >> 1) | ((previous & 1) << 7));
        }
        if (last_bit) v[0] ^= 0xe1;
    }
    return z;
}

// GHASH: xử lý lần lượt AAD, ciphertext rồi đến độ dài (đơn vị bit).
// Mỗi khối dưới 16 byte được thêm số 0 để đủ 16 byte.
void ghash_feed(Block& state, const Block& H, const Bytes& data) {
    for (std::size_t pos=0; pos<data.size(); pos+=16) {
        Block chunk{};
        std::size_t count = std::min<std::size_t>(16, data.size() - pos);
        for (std::size_t i = 0; i < count; ++i) chunk[i] = data[pos + i];
        state = gf128_mul(common::xor_block(state, chunk), H);
    }
}

void store_big_endian_64(Block& block, int offset, std::uint64_t number) {
    for (int i=7; i>=0; --i) {
        block[offset + i] = static_cast<Byte>(number & 0xff);
        number >>= 8;
    }
}

Block ghash(const Block& H, const Bytes& aad, const Bytes& cipher) {
    Block state{};
    ghash_feed(state, H, aad);
    ghash_feed(state, H, cipher);
    Block lengths{};
    store_big_endian_64(lengths, 0, static_cast<std::uint64_t>(aad.size()) * 8);
    store_big_endian_64(lengths, 8, static_cast<std::uint64_t>(cipher.size()) * 8);
    return gf128_mul(common::xor_block(state, lengths), H);
}

// 96-bit nonce || 0x00000001 tạo block J0 của GCM.
Block initial_j0(const Bytes& nonce) {
    if (nonce.size() != 12) throw std::invalid_argument("GCM nonce phai co 12 byte.");
    Block j0{};
    for (int i=0; i<12; ++i) j0[i] = nonce[i];
    j0[15] = 1;
    return j0;
}

// inc32 chỉ tăng 4 byte thấp nhất (không tăng cả 128 bit như CTR thông thường).
void increment32(Block& counter) {
    for (int i=15; i>=12; --i) {
        ++counter[i];
        if (counter[i] != 0) break;
    }
}

Bytes gctr(const AES& aes, const Bytes& data, Block counter) {
    Bytes result;
    for (std::size_t pos=0; pos<data.size(); pos+=16) {
        Block stream = aes.encrypt(counter);
        std::size_t count = std::min<std::size_t>(16, data.size()-pos);
        for (std::size_t i=0; i<count; ++i) result.push_back(data[pos+i] ^ stream[i]);
        increment32(counter);
    }
    return result;
}



// Encrypt: tạo ciphertext bằng CTR, sau đó tag xác thực bằng GHASH.
GcmResult gcm_encrypt(const AES& aes, const Bytes& plaintext,
                      const Bytes& nonce, const Bytes& aad) {
    Block j0 = initial_j0(nonce);
    Block H = aes.encrypt(Block{}); // H = AES_K(0^128)
    Block counter = j0;
    increment32(counter); // khởi đầu ở J0 + 1
    Bytes ciphertext = gctr(aes, plaintext, counter);
    Block tag = common::xor_block(aes.encrypt(j0), ghash(H, aad, ciphertext));
    return {ciphertext, tag};
}

// Decrypt: xác thực tag trước, sai tag phải từ chối giải mã.
// So sánh toàn bộ byte tag để tránh dừng ngay ở byte sai đầu tiên.
Bytes gcm_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& nonce,
                  const Bytes& aad, const Block& provided_tag) {
    Block j0 = initial_j0(nonce);
    Block H = aes.encrypt(Block{});
    Block expected_tag = common::xor_block(aes.encrypt(j0), ghash(H, aad, ciphertext));
    unsigned mismatch = 0;
    for (int i=0; i<16; ++i) mismatch |= expected_tag[i] ^ provided_tag[i];
    if (mismatch != 0) throw std::invalid_argument("GCM: tag khong dung, du lieu co the da bi sua.");
    Block counter = j0;
    increment32(counter);
    return gctr(aes, ciphertext, counter);
}


/* GMAC là GCM với plaintext rỗng: chỉ tạo tag từ AAD. */
Block gmac(const AES& aes,const Bytes& nonce,const Bytes& aad) {
    return gcm_encrypt(aes, Bytes{},nonce,aad).tag;
}
} // namespace nist
