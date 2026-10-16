#include "sp800_38a.hpp"
#include <algorithm>
namespace nist {
using Bytes=common::Bytes;

/* ===== SP 800-38A: ECB ===== */


// ECB: mỗi block plaintext được mã hóa độc lập.
// Sử dụng PKCS#7 cho dữ liệu dài bất kỳ, hoặc pad=false để kiểm thử chuẩn.
// Nhược điểm: hai block giống nhau sẽ tạo ra hai ciphertext block giống nhau.
Bytes ecb_encrypt(const AES& aes, Bytes data, bool pad) {
    if (pad) data = common::pkcs7_pad(data);
    common::require_blocks(data);
    Bytes result;
    for (std::size_t pos = 0; pos < data.size(); pos += 16) {
        common::append(result, aes.encrypt(common::block_at(data, pos)));
    }
    return result;
}

// Giải mã từng block độc lập và xóa padding khi có sử dụng.
Bytes ecb_decrypt(const AES& aes, const Bytes& ciphertext, bool unpad) {
    common::require_blocks(ciphertext);
    Bytes result;
    for (std::size_t pos = 0; pos < ciphertext.size(); pos += 16) {
        common::append(result, aes.decrypt(common::block_at(ciphertext, pos)));
    }
    return unpad ? common::pkcs7_unpad(result) : result;
}


/* ===== SP 800-38A: CBC ===== */


// CBC: trước khi mã hóa, XOR plaintext block với ciphertext trước.
// Block đầu XOR với IV. Phải dùng IV mới, ngẫu nhiên/không đoán trước cho mỗi lần mã hóa.
Bytes cbc_encrypt(const AES& aes, Bytes data, const Bytes& iv, bool pad) {
    common::require_iv(iv);
    if (pad) data = common::pkcs7_pad(data);
    common::require_blocks(data);
    Block previous = common::block_at(iv, 0);
    Bytes result;
    for (std::size_t pos = 0; pos < data.size(); pos += 16) {
        Block input = common::xor_block(common::block_at(data,pos), previous);
        Block output = aes.encrypt(input);
        common::append(result, output);
        previous = output;
    }
    return result;
}

// Giải mã CBC: P[i] = AES_decrypt(C[i]) XOR C[i-1], block đầu XOR IV.
Bytes cbc_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv, bool unpad) {
    common::require_iv(iv);
    common::require_blocks(ciphertext);
    Block previous = common::block_at(iv, 0);
    Bytes result;
    for (std::size_t pos=0; pos<ciphertext.size(); pos+=16) {
        Block current = common::block_at(ciphertext, pos);
        Block output = common::xor_block(aes.decrypt(current), previous);
        common::append(result, output);
        previous = current;
    }
    return unpad ? common::pkcs7_unpad(result) : result;
}


/* ===== SP 800-38A: CFB ===== */


// CFB-128: mã hóa IV/thanh ghi phản hồi thành keystream, XOR với plaintext.
// Sau mỗi block đủ 16 byte, ciphertext làm thanh ghi cho bước kế tiếp.
// Mã hóa và giải mã đều dùng aes.encrypt(), KHÔNG dùng aes.decrypt().
Bytes cfb128_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv) {
    common::require_iv(iv);
    Block feedback = common::block_at(iv, 0);
    Bytes ciphertext;
    for (std::size_t pos=0; pos<plaintext.size(); pos+=16) {
        Block stream = aes.encrypt(feedback);
        std::size_t count = std::min<std::size_t>(16, plaintext.size()-pos);
        for (std::size_t i=0; i<count; ++i) ciphertext.push_back(plaintext[pos+i] ^ stream[i]);
        if (count == 16) feedback = common::block_at(ciphertext, pos);
    }
    return ciphertext;
}

// Giải mã: plaintext = ciphertext XOR AES(feedback); cập nhật feedback bằng ciphertext.
Bytes cfb128_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv) {
    common::require_iv(iv);
    Block feedback = common::block_at(iv, 0);
    Bytes plaintext;
    for (std::size_t pos=0; pos<ciphertext.size(); pos+=16) {
        Block stream = aes.encrypt(feedback);
        std::size_t count = std::min<std::size_t>(16, ciphertext.size()-pos);
        for (std::size_t i=0; i<count; ++i) plaintext.push_back(ciphertext[pos+i] ^ stream[i]);
        if (count == 16) feedback = common::block_at(ciphertext, pos);
    }
    return plaintext;
}


/* ===== SP 800-38A: OFB ===== */


// OFB: mã hóa IV để tạo keystream, sau đó mã hóa chính keystream đó.
// Không dùng ciphertext để cập nhật feedback; encrypt/decrypt cùng một phép XOR.
// IV không được tái sử dụng với cùng key.
Bytes ofb_transform(const AES& aes, const Bytes& input, const Bytes& iv) {
    common::require_iv(iv);
    Block feedback = common::block_at(iv, 0);
    Bytes output;
    for (std::size_t pos=0; pos<input.size(); pos+=16) {
        feedback = aes.encrypt(feedback);
        std::size_t count = std::min<std::size_t>(16, input.size()-pos);
        for (std::size_t i=0; i<count; ++i) output.push_back(input[pos+i] ^ feedback[i]);
    }
    return output;
}


/* ===== SP 800-38A: CTR ===== */


// CTR: AES mã hóa giá trị counter thành keystream, XOR với dữ liệu.
// Sau mỗi block tăng counter 128-bit theo big-endian.
// Không được dùng lại cùng chuỗi counter cho cùng một key.
void increment_counter(Block& counter) {
    for (int i=15; i>=0; --i) {
        ++counter[i];
        if (counter[i] != 0) break; // nếu tràn 0xff -> 0x00 thì nhớ sang byte trước.
    }
}

Bytes ctr_transform(const AES& aes, const Bytes& input, const Bytes& initial_counter) {
    common::require_iv(initial_counter);
    Block counter = common::block_at(initial_counter, 0);
    Bytes output;
    for (std::size_t pos=0; pos<input.size(); pos+=16) {
        Block stream = aes.encrypt(counter);
        std::size_t count = std::min<std::size_t>(16, input.size()-pos);
        for (std::size_t i=0; i<count; ++i) output.push_back(input[pos+i] ^ stream[i]);
        increment_counter(counter);
    }
    return output;
}


/* CFB8: xử lý từng byte, thanh ghi phản hồi dịch 1 byte sau mỗi lượt. */
Bytes cfb8_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv) {
    common::require_iv(iv);
    Block register_block=common::block_at(iv,0);
    Bytes output;
    for(Byte p:plaintext) {
        Byte c=static_cast<Byte>(p ^ aes.encrypt(register_block)[0]);
        output.push_back(c);
        for(int i=0;i<15;++i) register_block[i]=register_block[i+1];
        register_block[15]=c;
    }
    return output;
}
Bytes cfb8_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv) {
    common::require_iv(iv);
    Block register_block=common::block_at(iv,0);
    Bytes output;
    for(Byte c:ciphertext) {
        output.push_back(static_cast<Byte>(c ^ aes.encrypt(register_block)[0]));
        for(int i=0;i<15;++i) register_block[i]=register_block[i+1];
        register_block[15]=c; // Giải mã cũng phản hồi CIPHERTEXT.
    }
    return output;
}
} // namespace nist
