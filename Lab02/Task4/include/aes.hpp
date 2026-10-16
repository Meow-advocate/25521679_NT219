#pragma once
#include <algorithm>
// Lớp AES chuyển từ Task 1, tách riêng để các chế độ tái sử dụng.
// Không sử dụng bất kỳ thư viện mật mã bên ngoài nào.

/*
  NT219 - LAB 2 - TASK 1: AES (C++)

  Mục tiêu: chuyển thuật toán AES từ Python sang C++, không dùng OpenSSL/Crypto++.
  AES nhận 1 khối (block) 16 byte, hỗ trợ khóa 16/24/32 byte.

  Thứ tự đọc code:
  1. Đổi dữ liệu HEX và khối 16 byte.
  2. Đổi khối 16 byte thành ma trận State 4x4 và ngược lại.
  3. SubBytes, ShiftRows, MixColumns, AddRoundKey.
  4. Key Expansion để tạo khóa cho từng vòng.
  5. encrypt/decrypt và kiểm thử kết quả.

  Nhớ: block (khối dữ liệu 16 byte) KHÁC round (vòng biến đổi AES).
  Phần xử lý HEX và hàm main() chỉ hỗ trợ nhập/xuất, kiểm thử bản C++.
*/
#include <array>        // std::array: ma trận State 4x4 và 1 block 16 byte
#include <cstdint>      // std::uint8_t: 1 byte 8 bit
#include <iomanip>      // in số hệ 16 (hex) đủ 2 ký tự
#include <iostream>     // nhập/xuất console
#include <sstream>      // ghép chuỗi kết quả hex
#include <stdexcept>    // thông báo lỗi khóa / block không hợp lệ
#include <string>       // xử lý chuỗi hex
#include <vector>       // khóa 16/24/32 byte, các word sinh khóa

// Đặt tên ngắn cho kiểu dữ liệu để các hàm bên dưới dễ đọc hơn.
using Byte = std::uint8_t;                   // 1 Byte = số nguyên không dấu 8 bit, từ 0 đến 255.
using Block = std::array<Byte, 16>;          // 1 block AES = 16 byte = 128 bit.
using Word = std::array<Byte, 4>;            // 1 word gồm 4 byte, dùng khi sinh khóa.
using State = std::array<std::array<Byte, 4>, 4>; // Ma trận 4 hàng x 4 cột.

// ===== PHẦN 1: ĐỔI CHUỖI HEX SANG BYTE VÀ NGƯỢC LẠI =====
// Khi test, dữ liệu được viết thành chuỗi hex, ví dụ "001122".
// Cứ 2 ký tự hex ứng với 1 byte: "00" -> 0x00, "11" -> 0x11.
// AES cần dùng byte thực sự để tính toán, không xử lý trực tiếp chuỗi.
inline int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';       // '0' -> 0, ..., '9' -> 9
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;  // 'a' -> 10, ..., 'f' -> 15
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;  // chấp nhận cả chữ hoa
    throw std::invalid_argument("Chuoi co ky tu khong phai he 16 (hex).");
}

inline std::vector<Byte> from_hex(const std::string& text) {
    if (text.size() % 2 != 0) throw std::invalid_argument("So ky tu hex phai chan.");
    std::vector<Byte> out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        // Ví dụ "1a": số 1 nằm ở 4 bit cao, a (=10) nằm ở 4 bit thấp.
        int high = hex_digit(text[i]);
        int low = hex_digit(text[i + 1]);
        Byte value = static_cast<Byte>((high << 4) | low);
        out.push_back(value);
    }
    return out;
}

// Phiên bản này chỉ in 1 block 16 byte, không cần template cho khó hiểu.
inline std::string to_hex(const Block& bytes) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0'); // hệ 16, thêm số 0 phía trước nếu cần.
    for (Byte b : bytes) {
        stream << std::setw(2) << static_cast<unsigned>(b); // ví dụ 0x0a -> "0a".
    }
    return stream.str();
}

inline Block to_block(const std::vector<Byte>& input) {
    if (input.size() != 16) {
        throw std::invalid_argument("Block AES phai chinh xac 16 byte (32 ky tu hex).");
    }
    Block result{};
    for (int i = 0; i < 16; ++i) {
        result[i] = input[i]; // chép lần lượt 16 byte vào mảng cố định.
    }
    return result;
}

// ===== PHẦN 2: LỚP AES =====
// Tương ứng class AES bên Python. Class gồm các hàm biến đổi và bộ khóa vòng.
// private: hàm nội bộ; public: hàm người dùng gọi được (encrypt, decrypt).
class AES {
private:
    // S-BOX: bảng tra 256 giá trị của chuẩn AES, KHÔNG phải giá trị tự đặt.
    // Ví dụ: byte 0x00 qua S_BOX sẽ thành 0x63; 0x53 thành 0xed.
    // inline/static/constexpr: bảng cố định được dùng chung trong lớp.
    inline static constexpr std::array<Byte, 256> S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // INV_S_BOX: bảng ngược dùng khi GIẢI MÃ.
    // Nếu mã hóa 0x00 -> 0x63 thì giải mã 0x63 -> 0x00.
    inline static constexpr std::array<Byte, 256> INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // RCON: các hằng số vòng dùng để sinh khóa AES.
    // Giá trị RCON chỉ XOR vào byte ĐẦU TIÊN của temp khi đến mốc i % Nk = 0.
    inline static constexpr std::array<Byte, 10> RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    int nk_ = 0;              // Nk = 4, 6, 8: khóa gốc có bao nhiêu word.
    int nr_ = 0;              // Nr = 10, 12, 14: số vòng mã hóa.
    std::vector<Word> words_; // Tất cả các word khóa sau khi Key Expansion.

    // ===== PHẦN 3: ĐỔI GIỮA BLOCK VÀ STATE =====
    // AES tính toán trên ma trận State 4x4. Phải điền THEO CỘT:
    // 00 44 88 cc
    // 11 55 99 dd
    // 22 66 aa ee
    // 33 77 bb ff
    // Công thức: byte ở vị trí (row,col) = block[4*col + row].
    static State bytes_to_state(const Block& block) {
        State state{};
        for (int col = 0; col < 4; ++col)
            for (int row = 0; row < 4; ++row)
                state[row][col] = block[4 * col + row]; // 4 byte liên tiếp thành 1 cột.
        return state;
    }

    // Sau khi AES tính xong, chuyển State 4x4 về mảng 16 byte, vẫn đọc theo cột.
    static Block state_to_bytes(const State& state) {
        Block block{};
        for (int col = 0; col < 4; ++col)
            for (int row = 0; row < 4; ++row)
                block[4 * col + row] = state[row][col];
        return block;
    }

    // ===== PHẦN 4: SUBBYTES =====
    // Đi qua cả 16 ô của State, thay mỗi byte x bằng S_BOX[x].
    // Trong Python có thể tách x thành hàng/cột bằng x//16 và x%16.
    // Thực ra 16*(x/16) + (x%16) = x (chia nguyên), nên C++ tra S_BOX[x] trực tiếp.
    static void sub_bytes(State& state) {
        for (int row = 0; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[row][col] = S_BOX[state[row][col]];
    }

    // InvSubBytes làm ngược SubBytes: tra giá trị qua bảng INV_S_BOX.
    static void inv_sub_bytes(State& state) {
        for (int row = 0; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[row][col] = INV_S_BOX[state[row][col]];
    }

    // ===== PHẦN 5: SHIFTROWS =====
    // Hàng 0 giữ nguyên, hàng 1 dịch trái 1, hàng 2 trái 2, hàng 3 trái 3.
    // Dịch VÒNG nghĩa là byte rời khỏi bên trái sẽ quay về bên phải.
    // Ví dụ [a,b,c,d] dịch trái 1 thành [b,c,d,a].
    static void shift_rows(State& state) {
        for (int row = 1; row < 4; ++row) {
            Byte old_row[4];
            for (int col = 0; col < 4; ++col) old_row[col] = state[row][col];
            for (int col = 0; col < 4; ++col) {
                state[row][col] = old_row[(col + row) % 4];
                // +row: dịch trái; %4: khi qua vị trí 3 thì quay về 0.
            }
        }
    }

    // InvShiftRows làm ngược: dịch VÒNG sang PHẢI số vị trí bằng chỉ số hàng.
    static void inv_shift_rows(State& state) {
        for (int row = 1; row < 4; ++row) {
            Byte old_row[4];
            for (int col = 0; col < 4; ++col) old_row[col] = state[row][col];
            for (int col = 0; col < 4; ++col) {
                state[row][col] = old_row[(col + 4 - row) % 4]; // dịch phải.
            }
        }
    }

    // ===== PHẦN 6: MIXCOLUMNS CẦN PHÉP NHÂN GF(2^8) =====
    // gmul(a,b) nhân 2 byte theo quy tắc của AES, không phải nhân thường.
    // Cách làm: xét lần lượt 8 bit của b; bit nào = 1 thì XOR a vào kết quả.
    // Mỗi lần a dịch trái 1 bit (nhân 2); nếu bit cao trước khi dịch = 1,
    // cần XOR với 0x1B để rút gọn trong trường GF(2^8).
    static Byte gmul(Byte a, Byte b) {
        Byte product = 0;
        for (int bit = 0; bit < 8; ++bit) {
            if (b & 1) product = static_cast<Byte>(product ^ a); // bit cuối b = 1 thì cộng a bằng XOR.
            const bool high_bit = (a & 0x80) != 0; // lưu xem a có bit cao nhất = 1.
            a = static_cast<Byte>(a << 1);  // giữ lại 8 bit thấp
            if (high_bit) a = static_cast<Byte>(a ^ 0x1b); // rút gọn theo đa thức AES.
            b = static_cast<Byte>(b >> 1);   // chuyển sang bit tiếp theo của b.
        }
        return product;
    }

    // MixColumns: trộn 4 byte TRONG CÙNG MỘT CỘT của State.
    // Hàng đầu của ma trận AES là [02,03,01,01], vì vậy:
    // byte mới b0 = gmul(02,a0) XOR gmul(03,a1) XOR a2 XOR a3.
    // Phải lưu a0..a3 trước khi sửa state, nếu không sẽ mất giá trị cũ.
    static void mix_columns(State& state) {
        for (int col = 0; col < 4; ++col) {
            Byte a0 = state[0][col], a1 = state[1][col];
            Byte a2 = state[2][col], a3 = state[3][col];
            state[0][col] = static_cast<Byte>(gmul(0x02,a0) ^ gmul(0x03,a1) ^ a2 ^ a3);
            state[1][col] = static_cast<Byte>(a0 ^ gmul(0x02,a1) ^ gmul(0x03,a2) ^ a3);
            state[2][col] = static_cast<Byte>(a0 ^ a1 ^ gmul(0x02,a2) ^ gmul(0x03,a3));
            state[3][col] = static_cast<Byte>(gmul(0x03,a0) ^ a1 ^ a2 ^ gmul(0x02,a3));
        }
    }

    // InvMixColumns: ma trận phép nhân NGƯỢC lại MixColumns.
    // Dùng các hệ số 0E, 0B, 0D, 09 thay cho 02, 03, 01, 01.
    static void inv_mix_columns(State& state) {
        for (int col = 0; col < 4; ++col) {
            Byte a0 = state[0][col], a1 = state[1][col];
            Byte a2 = state[2][col], a3 = state[3][col];
            state[0][col] = static_cast<Byte>(gmul(0x0e,a0)^gmul(0x0b,a1)^gmul(0x0d,a2)^gmul(0x09,a3));
            state[1][col] = static_cast<Byte>(gmul(0x09,a0)^gmul(0x0e,a1)^gmul(0x0b,a2)^gmul(0x0d,a3));
            state[2][col] = static_cast<Byte>(gmul(0x0d,a0)^gmul(0x09,a1)^gmul(0x0e,a2)^gmul(0x0b,a3));
            state[3][col] = static_cast<Byte>(gmul(0x0b,a0)^gmul(0x0d,a1)^gmul(0x09,a2)^gmul(0x0e,a3));
        }
    }

    // ===== PHẦN 7: ADDROUNDKEY =====
    // Mỗi vòng có khóa riêng gồm 16 byte (4 word).
    // XOR từng ô của State với byte khóa ở vị trí tương ứng.
    // Ví dụ 0x11 XOR 0x01 = 0x10. Giải mã cũng dùng XOR vì
    // (x XOR k) XOR k sẽ trả lại x.
    void add_round_key(State& state, int round) const {
        for (int col = 0; col < 4; ++col)
            for (int row = 0; row < 4; ++row)
                state[row][col] = static_cast<Byte>(
                    state[row][col] ^ words_[4 * round + col][row]);
    }

    // ===== PHẦN 8: KEY EXPANSION (SINH KHÓA CHO MỖI VÒNG) =====
    // RotWord: quay 1 word (4 byte) sang trái 1 byte:
    // [a,b,c,d] -> [b,c,d,a]. Khác ShiftRows vì đây là word của KHÓA.
    static Word rot_word(Word w) {
        Byte first = w[0];
        w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = first;
        return w;
    }

    // SubWord: thay lần lượt 4 byte trong word bằng bảng S_BOX.
    static Word sub_word(Word w) {
        for (Byte& b : w) b = S_BOX[b];
        return w;
    }

    // Key Expansion: mở rộng khóa gốc thành khóa cho từng vòng AES.
    // Cùng một quy tắc cho AES-128/192/256, chỉ khác Nk và Nr.
    // Bước 1: lấy khóa ban đầu, chia thành Nk word (mỗi word = 4 byte).
    // Bước 2: tính word mới từ w[i-Nk] XOR temp; temp = word ngay trước.
    //          Nếu i chia hết Nk thì RotWord -> SubWord -> XOR RCON.
    //          Riêng AES-256, i%8=4 thì SubWord thêm lần nữa.
    // Tổng cộng cần 4*(Nr+1) word vì mỗi round key là 4 word.
    void key_expansion(const std::vector<Byte>& key) {
        words_.clear();
        words_.reserve(static_cast<std::size_t>(4*(nr_+1)));
        // Đưa các word của khóa gốc vào danh sách trước.
        for (int i = 0; i < nk_; ++i) {
            Word word{};
            for (int j=0; j<4; ++j) word[j] = key[4*i+j];
            words_.push_back(word);
        }
        // Tạo các word còn thiếu từ word trước đó.
        for (int i = nk_; i < 4*(nr_+1); ++i) {
            Word temp = words_[i-1]; // tạm thời lấy word gần nhất.
            if (i % nk_ == 0) {
                temp = sub_word(rot_word(temp));
                temp[0] = static_cast<Byte>(temp[0] ^ RCON[i/nk_ - 1]);
            } else if (nk_ == 8 && i % 8 == 4) {
                temp = sub_word(temp);
            }
            Word next{};
            for (int j=0; j<4; ++j) {
                next[j] = static_cast<Byte>(words_[i-nk_][j] ^ temp[j]);
            }
            words_.push_back(next);
        }
    }


public:
    // Constructor: chạy một lần khi tạo đối tượng AES(key), tương ứng __init__.
    // Kiểm tra key dài 16/24/32 byte, tính Nk/Nr, rồi sinh các round key.
    explicit AES(const std::vector<Byte>& key) {
        if (key.size()!=16 && key.size()!=24 && key.size()!=32) {
            throw std::invalid_argument("AES key phai la 16, 24 hoac 32 byte.");
        }
        nk_ = static_cast<int>(key.size()/4); // 4 / 6 / 8
        nr_ = nk_ + 6;                      // 10 / 12 / 14
        key_expansion(key);
    }

    int key_bits() const { return 32 * nk_; }  // 128,192,256
    int rounds() const { return nr_; }

    // ===== PHẦN 9: MÃ HÓA 1 BLOCK =====
    // Bước đầu: XOR dữ liệu với khóa vòng số 0.
    // Các vòng giữa: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
    // Vòng cuối: không làm MixColumns (theo chuẩn AES).
    Block encrypt(const Block& input) const {
        State state = bytes_to_state(input);
        add_round_key(state, 0);

        for (int round = 1; round < nr_; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, nr_);
        return state_to_bytes(state);
    }

    // ===== PHẦN 10: GIẢI MÃ 1 BLOCK =====
    // Thực hiện các phép đảo theo thứ tự ngược với quá trình mã hóa.
    // Dùng khóa vòng từ Nr về 0 để khôi phục đúng plaintext 16 byte.
    Block decrypt(const Block& input) const {
        State state = bytes_to_state(input);
        add_round_key(state, nr_);
        for (int round = nr_ - 1; round >= 1; --round) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0);
        return state_to_bytes(state);
    }
};

// Các công cụ dùng chung để triển khai modes trong Task 2.
// Chúng xử lý mảng byte, không thay thế thuật toán AES.
namespace common {
    using Bytes = std::vector<Byte>;

    inline Bytes parse_hex(const std::string& input) { return from_hex(input); }

    inline std::string hex(const Bytes& value) {
        const char* digits = "0123456789abcdef";
        std::string out;
        for (Byte b : value) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0x0f]);
        }
        return out;
    }

    inline Block block_at(const Bytes& bytes, std::size_t position) {
        if (bytes.size() - position < 16) throw std::invalid_argument("Khong du 16 byte cho 1 block.");
        Block block{};
        for (int i = 0; i < 16; ++i) block[i] = bytes[position + i];
        return block;
    }

    inline Bytes pkcs7_pad(Bytes data) {
        Byte n = static_cast<Byte>(16 - data.size() % 16);
        for (int i = 0; i < n; ++i) data.push_back(n);
        return data;
    }

    inline Bytes pkcs7_unpad(Bytes data) {
        if (data.empty() || data.size() % 16 != 0) throw std::invalid_argument("Padding khong hop le.");
        Byte n = data.back();
        if (n == 0 || n > 16) throw std::invalid_argument("Padding length khong hop le.");
        for (std::size_t i = data.size() - n; i < data.size(); ++i)
            if (data[i] != n) throw std::invalid_argument("Padding bytes khong hop le.");
        data.resize(data.size() - n);
        return data;
    }

    inline void require_blocks(const Bytes& data) {
        if (data.empty() || data.size() % 16 != 0)
            throw std::invalid_argument("Can so byte la boi so duong cua 16.");
    }

    inline void require_iv(const Bytes& iv) {
        if (iv.size() != 16) throw std::invalid_argument("IV/counter ban dau phai dung 16 byte.");
    }

    inline Block xor_block(Block left, const Block& right) {
        for (int i = 0; i < 16; ++i) left[i] ^= right[i];
        return left;
    }

    inline void append(Bytes& out, const Block& block) {
        out.insert(out.end(), block.begin(), block.end());
    }

    inline bool report(const std::string& mode, const Bytes& actual,
                       const Bytes& expected, const Bytes& plain, const Bytes& recovered) {
        bool enc_ok = actual == expected;
        bool dec_ok = plain == recovered;
        std::cout << "AES-128-" << mode << " Known-Answer Test\n"
                  << "Expected : " << hex(expected) << "\n"
                  << "Computed : " << hex(actual) << "\n"
                  << "Encrypt  : " << (enc_ok ? "PASS" : "FAIL") << "\n"
                  << "Decrypt  : " << (dec_ok ? "PASS" : "FAIL") << "\n"
                  << (enc_ok && dec_ok ? "ALL TESTS PASSED" : "TEST FAILED") << "\n";
        return enc_ok && dec_ok;
    }
}
