#include "rsa_encoding.hpp"
#include "key_io.hpp"
#include "task_cli.hpp"
#include "ossl_raii.hpp"
// Lab 03 - Task C: Chuyển đổi OS2IP/I2OSP, RSA không đệm và RSA-OAEP.

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fstream>
#include <filesystem>
#include <string_view>
#include <limits>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace task_c {

using namespace std;
using Bytes = vector<unsigned char>;
using Big = unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BnContext = unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using RsaKey = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using RsaContext = unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

// Mã thoát theo quy định của đề bài (G1-G3):
// 0: thành công; 1: lỗi cú pháp hoặc đầu vào; 2: lỗi đọc/ghi;
// 3: dữ liệu sai định dạng; 4: lỗi mật mã; 5: lỗi nội bộ hoặc OpenSSL.
using LabError = lab::Error;

int totalChecks = 0;
int failedChecks = 0;

void check(const string& label, bool passed) {
    ++totalChecks;
    if (!passed) ++failedChecks;
    cout << (passed ? "[PASS] " : "[FAIL] ") << label << '\n';
}
void require(bool ok, const string& description, int exitCode = 5) {
    if (!ok) throw LabError(exitCode, description);
}
Big newBig() {
    Big x(BN_new(), BN_clear_free);
    require(bool(x), "Khong cap phat duoc BIGNUM");
    return x;
}
BnContext newBnContext() {
    BnContext ctx(BN_CTX_new(), BN_CTX_free);
    require(bool(ctx), "Khong cap phat duoc BN_CTX");
    return ctx;
}

// OS2IP theo RFC 8017: byte đầu tiên có trọng số cao nhất.
Big os2ip(const Bytes& bytes) {
    require(bytes.size() <= 1024, "OS2IP gioi han 1024 bytes", 1);
    Big number = newBig();
    if (bytes.empty()) {
        BN_zero(number.get());
    } else {
        require(BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), number.get()) != nullptr,
                "OS2IP that bai");
    }
    return number;
}

// I2OSP trả về đúng số byte được yêu cầu, bổ sung byte 00 ở đầu nếu cần.
// Từ chối giá trị âm hoặc giá trị không biểu diễn được trong độ dài đã cho.
Bytes i2osp(const BIGNUM* x, size_t width) {
    require(x && !BN_is_negative(x), "I2OSP khong chap nhan so am", 1);
    require(width <= 1024, "I2OSP: width vuot gioi han 1024 bytes", 1);
    if (width == 0) {
        require(BN_is_zero(x), "I2OSP: integer too large", 1);
        return {};
    }
    Bytes output(width, 0);
    require(BN_bn2binpad(x, output.data(), static_cast<int>(width)) >= 0,
            "I2OSP: integer too large", 1);
    return output;
}

Bytes fromHex(const string& hex) {
    require(hex.size() <= 2048, "OS2IP gioi han 1024 bytes", 1);
    require(hex.size() % 2 == 0, "Hex phai co so ky tu chan", 1);
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw LabError(1, "Ky tu hex khong hop le");
    };
    Bytes result;
    for (size_t i = 0; i < hex.size(); i += 2)
        result.push_back(static_cast<unsigned char>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    return result;
}
string toHex(const Bytes& bytes, size_t showMax = 32) {
    ostringstream out;
    out << hex << setfill('0');
    for (size_t i = 0; i < min(bytes.size(), showMax); ++i)
        out << setw(2) << static_cast<unsigned int>(bytes[i]);
    if (bytes.size() > showMax) out << "... (" << dec << bytes.size() << " bytes)";
    return out.str();
}

// 1. Kiểm tra các trường hợp chuyển đổi C-T1 đến C-T6.
void part1() {
    cout << "\n===== PART 1: OS2IP / I2OSP =====\n";
    struct Case { const char* id; const char* bytes; size_t width; const char* expected; };
    const Case cases[] = {
        {"C-T1", "000001", 3, "000001"},
        {"C-T2", "000001", 1, "01"},
        {"C-T3", "0100",   2, "0100"},
        {"C-T4", "0100",   1, nullptr},  // Số 256 cần ít nhất hai byte để biểu diễn.
        {"C-T5", "00ff00", 3, "00ff00"},
        {"C-T6", "",       2, "0000"}
    };
    for (const auto& test : cases) {
        auto number = os2ip(fromHex(test.bytes));
        char* decimal = BN_bn2dec(number.get());
        require(decimal != nullptr, "BN_bn2dec that bai");
        cout << test.id << " | OS2IP=" << decimal << " | I2OSP(" << test.width << ")=";
        OPENSSL_free(decimal);
        bool succeeded = false;
        Bytes output;
        try {
            output = i2osp(number.get(), test.width);
            succeeded = true;
        } catch (const runtime_error&) {
            // Đây là trường hợp lỗi được mong đợi khi số nguyên vượt quá độ dài cho phép.
        }
        cout << (succeeded ? toHex(output) : "integer too large") << '\n';
        check(test.id, test.expected ? (succeeded && toHex(output) == test.expected) : !succeeded);
    }
}

// 2. RSA không đệm với bộ tham số minh họa n = 3233, e = 17, d = 2753.
// Không có cơ chế đệm nên bản mã có tính xác định và dễ bị biến đổi.
void part2() {
    cout << "\n===== PART 2: TEXTBOOK RSA (TOY EXAMPLE) =====\n";
    auto ctx = newBnContext();
    auto n = newBig(), e = newBig(), d = newBig();
    auto m = newBig(), c = newBig(), cAgain = newBig(), back = newBig();
    auto six = newBig(), seven = newBig(), encSix = newBig(), encSeven = newBig();
    auto forged = newBig();
    require(BN_set_word(n.get(), 3233) && BN_set_word(e.get(), 17) &&
            BN_set_word(d.get(), 2753) && BN_set_word(m.get(), 65) &&
            BN_set_word(six.get(), 6) && BN_set_word(seven.get(), 7), "Khoi tao khoa toy that bai");
    require(BN_mod_exp(c.get(), m.get(), e.get(), n.get(), ctx.get()) == 1, "Ma hoa toy that bai");
    require(BN_mod_exp(back.get(), c.get(), d.get(), n.get(), ctx.get()) == 1, "Giai ma toy that bai");
    cout << "Toy key: n=3233, e=17, d=2753\n";
    cout << "Enc(65)=" << BN_get_word(c.get()) << ", Dec(Enc(65))=" << BN_get_word(back.get()) << '\n';
    check("Enc(65)=2790; decrypt=65", BN_is_word(c.get(), 2790) && BN_is_word(back.get(), 65));
    require(BN_mod_exp(cAgain.get(), m.get(), e.get(), n.get(), ctx.get()) == 1, "Ma hoa lan hai loi");
    check("Determinism: Enc(65) lan 1 = lan 2", BN_cmp(c.get(), cAgain.get()) == 0);
    require(BN_mod_exp(encSix.get(), six.get(), e.get(), n.get(), ctx.get()) == 1 &&
            BN_mod_exp(encSeven.get(), seven.get(), e.get(), n.get(), ctx.get()) == 1 &&
            BN_mod_mul(forged.get(), encSix.get(), encSeven.get(), n.get(), ctx.get()) == 1 &&
            BN_mod_exp(back.get(), forged.get(), d.get(), n.get(), ctx.get()) == 1,
            "Phep thu tinh uon deo RSA loi");
    cout << "C-T9: Enc(6)=" << BN_get_word(encSix.get())
         << ", Enc(7)=" << BN_get_word(encSeven.get())
         << ", forged=(Enc(6)*Enc(7)) mod n=" << BN_get_word(forged.get())
         << ", decrypted=" << BN_get_word(back.get()) << '\n';
    check("C-T9: 824 * 2369 mod 3233 = 2557; decrypt = 42",
          BN_is_word(encSix.get(), 824) && BN_is_word(encSeven.get(), 2369)
          && BN_is_word(forged.get(), 2557) && BN_is_word(back.get(), 42));
}

// Sinh khóa RSA 2048 bit trong bộ nhớ để kiểm tra OAEP, không ghi khóa ra tệp.
RsaKey newRsaKey() {
    RsaContext ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    require(bool(ctx), "Khong tao duoc EVP_PKEY_CTX");
    require(EVP_PKEY_keygen_init(ctx.get()) > 0, "EVP_PKEY_keygen_init loi");
    require(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) > 0, "Dat bits RSA loi");
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_generate(ctx.get(), &raw) > 0 && raw != nullptr, "Sinh khoa RSA that bai");
    return RsaKey(raw, EVP_PKEY_free);
}
Big rsaParam(EVP_PKEY* key, const char* name) {
    BIGNUM* raw = nullptr;
    require(EVP_PKEY_get_bn_param(key, name, &raw) == 1 && raw != nullptr,
            "Khong lay duoc tham so RSA");
    return Big(raw, BN_clear_free);
}

// Thực hiện phép toán RSA cơ bản bằng lũy thừa modulo với BIGNUM.
Bytes rawRsa(const Bytes& x, const BIGNUM* exponent, const BIGNUM* modulus, size_t k) {
    auto value = os2ip(x);
    require(BN_cmp(value.get(), modulus) < 0, "Dai dien RSA vuot pham vi n", 1);
    auto result = newBig();
    auto ctx = newBnContext();
    require(BN_mod_exp(result.get(), value.get(), exponent, modulus, ctx.get()) == 1,
            "Phep luy thua RSA that bai");
    return i2osp(result.get(), k);
}

Bytes sha256(const Bytes& data) {
    Bytes digest(32);
    unsigned int written = 0;
    require(EVP_Digest(data.data(), data.size(), digest.data(), &written, EVP_sha256(), nullptr) == 1
            && written == 32, "SHA-256 that bai");
    return digest;
}

// MGF1 với SHA-256 theo RFC 8017: băm seed ghép với bộ đếm dài bốn byte.
Bytes mgf1(const Bytes& seed, size_t requested) {
    Bytes out;
    out.reserve(requested);
    for (uint32_t counter = 0; out.size() < requested; ++counter) {
        Bytes input = seed;
        input.push_back(static_cast<unsigned char>((counter >> 24) & 0xff));
        input.push_back(static_cast<unsigned char>((counter >> 16) & 0xff));
        input.push_back(static_cast<unsigned char>((counter >> 8) & 0xff));
        input.push_back(static_cast<unsigned char>(counter & 0xff));
        Bytes block = sha256(input);
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(requested);
    return out;
}

// EME-OAEP: EM = 0x00 || maskedSeed || maskedDB; sử dụng nhãn rỗng.
Bytes oaepEncode(const Bytes& message, size_t k) {
    constexpr size_t hLen = 32;
    require(k >= 2 * hLen + 2, "OAEP: modulus too small");
    require(message.size() <= k - 2 * hLen - 2,
            "OAEP: message too long", 1);
    Bytes db = sha256({});
    db.insert(db.end(), k - message.size() - 2 * hLen - 2, 0x00);
    db.push_back(0x01);
    db.insert(db.end(), message.begin(), message.end());
    Bytes seed(hLen);
    require(RAND_bytes(seed.data(), static_cast<int>(hLen)) == 1, "RAND_bytes that bai");
    Bytes dbMask = mgf1(seed, db.size());
    for (size_t i = 0; i < db.size(); ++i) db[i] ^= dbMask[i];
    Bytes seedMask = mgf1(db, hLen);
    for (size_t i = 0; i < hLen; ++i) seed[i] ^= seedMask[i];
    Bytes em = {0x00};
    em.insert(em.end(), seed.begin(), seed.end());
    em.insert(em.end(), db.begin(), db.end());
    return em;
}

// Hàm giải mã OAEP tự cài đặt chỉ phục vụ thử nghiệm, không bảo đảm thời gian thực thi hằng.
// Khi cần giải mã an toàn, sử dụng EVP_PKEY_decrypt của OpenSSL.
bool oaepDecode(const Bytes& em, Bytes& message) {
    constexpr size_t hLen = 32;
    if (em.size() < 2 * hLen + 2) return false;
    Bytes seed(em.begin() + 1, em.begin() + 1 + hLen);
    Bytes db(em.begin() + 1 + hLen, em.end());
    Bytes seedMask = mgf1(db, hLen);
    for (size_t i = 0; i < hLen; ++i) seed[i] ^= seedMask[i];
    Bytes dbMask = mgf1(seed, db.size());
    for (size_t i = 0; i < db.size(); ++i) db[i] ^= dbMask[i];
    Bytes expectedHash = sha256({});
    if (em[0] != 0 || CRYPTO_memcmp(db.data(), expectedHash.data(), hLen) != 0) return false;
    size_t index = hLen;
    while (index < db.size() && db[index] == 0) ++index;
    if (index == db.size() || db[index] != 0x01) return false;
    message.assign(db.begin() + index + 1, db.end());
    return true;
}

RsaContext newOaepContext(EVP_PKEY* key, bool encrypt) {
    RsaContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), EVP_PKEY_CTX_free);
    require(bool(ctx), "Khong tao duoc OAEP context");
    require((encrypt ? EVP_PKEY_encrypt_init(ctx.get()) : EVP_PKEY_decrypt_init(ctx.get())) > 0,
            "Khoi tao EVP OAEP that bai");
    require(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) > 0 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) > 0,
            "Thiet lap OAEP SHA-256/MGF1 loi");
    return ctx;
}
Bytes opensslEncrypt(EVP_PKEY* key, const Bytes& plain) {
    const int keySize = EVP_PKEY_get_size(key);
    require(keySize >= 66, "OAEP: invalid key length", 3);
    require(plain.size() <= static_cast<size_t>(keySize - 66),
            "OAEP: message too long", 1);
    auto ctx = newOaepContext(key, true);
    size_t length = 0;
    require(EVP_PKEY_encrypt(ctx.get(), nullptr, &length, plain.data(), plain.size()) > 0,
            "Khong tinh duoc do dai ciphertext");
    Bytes result(length);
    require(EVP_PKEY_encrypt(ctx.get(), result.data(), &length, plain.data(), plain.size()) > 0,
            "EVP_PKEY_encrypt that bai");
    result.resize(length);
    return result;
}
// C-T11 gọi trực tiếp EVP để kiểm tra việc từ chối thông điệp dài 319 byte.
// Phép kiểm tra này độc lập với bước kiểm tra độ dài trong opensslEncrypt.
bool evpRejectsOversizedMessage(EVP_PKEY* key, const Bytes& message) {
    auto ctx = newOaepContext(key, true);
    size_t outputLength = static_cast<size_t>(EVP_PKEY_get_size(key));
    Bytes ciphertext(outputLength);
    int ok = EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outputLength,
                              message.data(), message.size());
    if (ok <= 0) ERR_clear_error();
    return ok <= 0;
}

bool opensslDecrypt(EVP_PKEY* key, const Bytes& cipher, Bytes& plain) {
    auto ctx = newOaepContext(key, false);
    size_t length = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &length, cipher.data(), cipher.size()) <= 0) {
        ERR_clear_error();
        return false;
    }
    Bytes output(length);
    if (EVP_PKEY_decrypt(ctx.get(), output.data(), &length, cipher.data(), cipher.size()) <= 0) {
        ERR_clear_error();
        return false;
    }
    output.resize(length);
    plain = move(output);
    return true;
}

void part3() {
    cout << "\n===== PART 3: RSA-OAEP SHA-256 / MGF1 =====\n";
    auto key = newRsaKey();
    auto n = rsaParam(key.get(), OSSL_PKEY_PARAM_RSA_N);
    auto e = rsaParam(key.get(), OSSL_PKEY_PARAM_RSA_E);
    auto d = rsaParam(key.get(), OSSL_PKEY_PARAM_RSA_D);
    const size_t k = static_cast<size_t>(EVP_PKEY_get_size(key.get()));
    const string text = "attack at dawn";
    Bytes message(text.begin(), text.end());
    cout << "RSA=" << EVP_PKEY_get_bits(key.get()) << " bits, k=" << k
         << " bytes, message=\"" << text << "\"\n";

    // Chiều 1: tự mã hóa OAEP, thực hiện RSA cơ bản rồi giải mã bằng OpenSSL.
    Bytes ourEncoded = oaepEncode(message, k);
    Bytes ourCipher = rawRsa(ourEncoded, e.get(), n.get(), k);
    Bytes recovered;
    cout << "Manual OAEP encoded (hex): " << toHex(ourEncoded, 16) << '\n';
    check("Custom OAEP encrypt -> OpenSSL decrypt",
          opensslDecrypt(key.get(), ourCipher, recovered) && recovered == message);

    // Chiều 2: mã hóa bằng OpenSSL, thực hiện RSA với d rồi tự giải mã OAEP.
    Bytes officialCipher = opensslEncrypt(key.get(), message);
    Bytes officialEncoded = rawRsa(officialCipher, d.get(), n.get(), k);
    Bytes decoded;
    cout << "OpenSSL OAEP encoded (hex): " << toHex(officialEncoded, 16) << '\n';
    check("OpenSSL encrypt -> Custom OAEP decode",
          oaepDecode(officialEncoded, decoded) && decoded == message);

    // OAEP sử dụng seed ngẫu nhiên nên hai lần mã hóa cùng thông điệp cho bản mã khác nhau.
    Bytes secondCipher = opensslEncrypt(key.get(), message);
    check("OAEP is randomized (two ciphertexts differ)", officialCipher != secondCipher);

    // RSA 2048 bit với SHA-256: độ dài thông điệp tối đa là 256 - 64 - 2 = 190 byte.
    const size_t maxLength = k - 2 * 32 - 2;
    Bytes maxMessage(maxLength, 'A');
    Bytes maxCipher = opensslEncrypt(key.get(), maxMessage);
    check("OAEP maximum 190-byte message round-trip",
          maxLength == 190 && opensslDecrypt(key.get(), maxCipher, recovered) && recovered == maxMessage);
    bool tooLongRejected = false;
    try { (void)oaepEncode(Bytes(maxLength + 1, 'B'), k); }
    catch (const runtime_error&) { tooLongRejected = true; }
    check("OAEP rejects 191-byte message", tooLongRejected);

    // Thay đổi một bit trong bản mã phải làm cho quá trình giải mã OAEP thất bại.
    Bytes tampered = officialCipher;
    tampered[10] ^= 0x01;
    check("OAEP rejects tampered ciphertext (1 bit flipped)",
          !opensslDecrypt(key.get(), tampered, recovered));

    // Kiểm tra phép biến đổi nhân: nhân bản mã OAEP với giá trị mã hóa của số 2.
    // Cấu trúc đệm OAEP khiến bản mã bị biến đổi không vượt qua bước kiểm tra hợp lệ.
    auto multiplier = newBig();
    auto cipherInteger = os2ip(officialCipher);
    auto encryptedTwo = newBig();
    auto changedInteger = newBig();
    auto bnctx = newBnContext();
    require(BN_set_word(multiplier.get(), 2) == 1 &&
            BN_mod_exp(encryptedTwo.get(), multiplier.get(), e.get(), n.get(), bnctx.get()) == 1 &&
            BN_mod_mul(changedInteger.get(), cipherInteger.get(), encryptedTwo.get(), n.get(), bnctx.get()) == 1,
            "Khong tao duoc ban ma RSA da bien doi");
    Bytes changedCipher = i2osp(changedInteger.get(), k);
    check("OAEP rejects multiplicatively modified ciphertext",
          !opensslDecrypt(key.get(), changedCipher, recovered));
}


// C-T10: sinh khóa RSA học thuật từ 512 đến 1024 bit.
// Không đọc khóa từ tệp và không sử dụng khóa học thuật cho lệnh OAEP an toàn.
void educationalRawRsa(int bits) {
    require(bits >= 512 && bits <= 1024, "raw-rsa: --bits phai trong [512, 1024]", 1);
    cout << "\nEDUCATIONAL - INSECURE: TEXTBOOK RSA, NEVER USE FOR REAL DATA\n";
    cout << "===== C-T10: RAW RSA (" << bits << " bits) =====\n";
    // Áp dụng quy trình sinh tham số RSA học thuật đã sử dụng ở Task B.
    // Sinh p, q bằng BIGNUM rồi tính n, phi, lambda và d; không dùng EVP_RSA_gen.
    auto ctxGen = newBnContext();
    auto p = newBig(), q = newBig(), pm1 = newBig(), qm1 = newBig();
    auto n = newBig(), e = newBig(), phi = newBig(), lambda = newBig();
    auto g = newBig();
    require(BN_set_word(e.get(), 65537) == 1, "Khong thiet lap duoc e=65537");
    auto drawPrime = [&](BIGNUM* prime, BIGNUM* primeMinusOne) {
        do {
            require(BN_generate_prime_ex2(prime, bits/2, 0, nullptr, nullptr,
                                          nullptr, ctxGen.get()) == 1,
                    "Sinh so nguyen to RSA hoc thuat that bai");
            require(BN_copy(primeMinusOne, prime) != nullptr &&
                    BN_sub_word(primeMinusOne, 1) == 1 &&
                    BN_gcd(g.get(), e.get(), primeMinusOne, ctxGen.get()) == 1,
                    "Kiem tra gcd(e, prime-1) that bai");
        } while (!BN_is_one(g.get()));
    };
    drawPrime(p.get(), pm1.get());
    do { drawPrime(q.get(), qm1.get()); } while (BN_cmp(p.get(), q.get()) == 0);
    require(BN_mul(n.get(), p.get(), q.get(), ctxGen.get()) == 1 &&
            BN_mul(phi.get(), pm1.get(), qm1.get(), ctxGen.get()) == 1 &&
            BN_gcd(g.get(), pm1.get(), qm1.get(), ctxGen.get()) == 1 &&
            BN_div(lambda.get(), nullptr, phi.get(), g.get(), ctxGen.get()) == 1,
            "Tinh n, phi, lambda cua RSA that bai");
    Big d(BN_mod_inverse(nullptr, e.get(), lambda.get(), ctxGen.get()), BN_clear_free);
    require(bool(d), "Tinh d=e^-1 mod lambda that bai");
    const size_t k = static_cast<size_t>(BN_num_bytes(n.get()));
    cout << "Generated with BN_generate_prime_ex2 + Task B formulas: "
         << BN_num_bits(n.get()) << "-bit modulus, e=65537\n";
    vector<Bytes> samples = {
        fromHex("000001"), fromHex("0100"), fromHex("00ff00"), Bytes{},
        fromHex("01"), fromHex("000000")
    };
    Bytes random32(32);
    require(RAND_bytes(random32.data(), 32) == 1, "RAND_bytes raw RSA that bai");
    random32[0] = 0;
    samples.push_back(random32);
    bool allRoundTrips = true;
    for (size_t i = 0; i < samples.size(); ++i) {
        const auto& x = samples[i];
        auto xi = os2ip(x);
        if (BN_cmp(xi.get(), n.get()) >= 0) { allRoundTrips = false; continue; }
        Bytes ciphertext = rawRsa(x, e.get(), n.get(), k);
        Bytes recoveredFull = rawRsa(ciphertext, d.get(), n.get(), k);
        auto recoveredInteger = os2ip(recoveredFull);
        Bytes recovered = i2osp(recoveredInteger.get(), x.size());
        bool ok = recovered == x;
        allRoundTrips &= ok;
        cout << "Round-trip X=" << toHex(x, 32) << " -> " << toHex(recovered, 32)
             << (ok ? " [OK]" : " [FAIL]") << '\n';
    }
    check("C-T10 all fixed-width RSA round-trips", allRoundTrips);
    // Từ chối giá trị x = n vì RSA chỉ chấp nhận 0 <= x < n.
    bool rejectedRange = false;
    try { (void)rawRsa(i2osp(n.get(), k), e.get(), n.get(), k); }
    catch (const LabError& error) { rejectedRange = error.code == 1; }
    check("C-T10 range check rejects x >= n", rejectedRange);
    Bytes m = fromHex("41");
    Bytes c1 = rawRsa(m, e.get(), n.get(), k);
    Bytes c2 = rawRsa(m, e.get(), n.get(), k);
    check("C-T10 determinism (same plaintext -> same ciphertext)", c1 == c2);
    Bytes enc6 = rawRsa(fromHex("06"), e.get(), n.get(), k);
    Bytes enc7 = rawRsa(fromHex("07"), e.get(), n.get(), k);
    auto a = os2ip(enc6), b = os2ip(enc7), forged = newBig();
    auto ctx = newBnContext();
    require(BN_mod_mul(forged.get(), a.get(), b.get(), n.get(), ctx.get()) == 1,
            "C-T10 tao ciphertext lien he that bai");
    Bytes decrypted = rawRsa(i2osp(forged.get(), k), d.get(), n.get(), k);
    auto plaintext = os2ip(decrypted);
    check("C-T10 malleability: decrypt(Enc(6)*Enc(7))=42", BN_is_word(plaintext.get(),42));
}

// Phân tích tham số dòng lệnh, kiểm tra định dạng và giới hạn độ dài đầu vào.
size_t parseSize(const string& s, size_t maximum) {
    require(!s.empty() && s.find_first_not_of("0123456789") == string::npos,
            "Tham so phai la so nguyen khong am", 1);
    size_t result = 0;
    for (char c : s) {
        size_t digit = static_cast<size_t>(c-'0');
        require(digit <= maximum && result <= (maximum-digit)/10, "Tham so qua lon", 1);
        result = result*10+digit;
    }
    require(result <= maximum, "Tham so qua lon", 1);
    return result;
}
string bnDecimal(const BIGNUM* x) {
    char* txt = BN_bn2dec(x);
    require(txt != nullptr, "BN_bn2dec failed");
    string result(txt);
    OPENSSL_free(txt);
    return result;
}

// Đọc khóa PEM hoặc DER theo các định dạng đã sử dụng ở Task B.
// Khóa công khai sử dụng SPKI, khóa riêng sử dụng PKCS#8.
// Phần đọc khóa được tách riêng để có thể sử dụng lại khi tích hợp dự án.
// Bộ đệm chứa khóa riêng được xóa khi ra khỏi phạm vi, kể cả khi có ngoại lệ.
// Tránh sao chép khóa PEM riêng sang std::string để hạn chế lưu dữ liệu nhạy cảm.
struct FileKeyBytes {
    Bytes data;
    bool secret;
    explicit FileKeyBytes(bool isPrivate) : secret(isPrivate) {}
    ~FileKeyBytes() {
        if (secret && !data.empty()) OPENSSL_cleanse(data.data(), data.size());
    }
    FileKeyBytes(const FileKeyBytes&) = delete;
    FileKeyBytes& operator=(const FileKeyBytes&) = delete;
};

RsaKey readKey(const string& name, bool privateKey) {
    constexpr size_t MAX_KEY_FILE_BYTES = 1024 * 1024;
    ifstream stream(name, ios::binary | ios::ate);
    require(bool(stream), "Khong mo duoc file khoa: " + name, 2);
    const auto end = stream.tellg();
    require(end >= 0, "Khong xac dinh duoc kich thuoc file khoa", 2);
    const auto length = static_cast<uint64_t>(end);
    require(length > 0 && length <= MAX_KEY_FILE_BYTES,
            "Kich thuoc file khoa khong hop le", 3);
    stream.seekg(0, ios::beg);
    require(bool(stream), "Khong doc duoc file khoa: " + name, 2);
    FileKeyBytes input(privateKey);
    input.data.resize(static_cast<size_t>(length));
    require(bool(stream.read(reinterpret_cast<char*>(input.data.data()),
                             static_cast<streamsize>(length))),
            "Khong doc duoc day du file khoa: " + name, 2);

    const Bytes& bytes = input.data;
    string_view data(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    const bool pem = data.rfind("-----BEGIN ", 0) == 0;
    EVP_PKEY* raw = nullptr;
    if (pem) {
        // Chỉ chấp nhận PKCS#8 cho khóa riêng và SPKI cho khóa công khai; từ chối dữ liệu thừa.
        const string_view beginLabel = privateKey ? "-----BEGIN PRIVATE KEY-----" :
                                                    "-----BEGIN PUBLIC KEY-----";
        const string_view endLabel = privateKey ? "-----END PRIVATE KEY-----" :
                                                  "-----END PUBLIC KEY-----";
        require(data.rfind(beginLabel, 0) == 0, "PEM khong dung SPKI/PKCS#8", 3);
        const auto pos = data.find(endLabel, beginLabel.size());
        require(pos != string_view::npos, "Khong tim thay ket thuc PEM", 3);
        require(pos > 0 && data[pos - 1] == '\n', "Thieu dong ket thuc PEM", 3);
        const auto tail = data.substr(pos + endLabel.size());
        require(tail.find_first_not_of(" \r\n\t") == string_view::npos,
                "PEM co du lieu thua", 3);
        unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free);
        require(bool(bio), "BIO_new_mem_buf loi");
        raw = privateKey ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
                         : PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    } else {
        const unsigned char* cursor = bytes.data();
        if (privateKey) {
            unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> info(
                d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, static_cast<long>(bytes.size())),
                PKCS8_PRIV_KEY_INFO_free);
            require(bool(info), "DER phai la PKCS#8 private key", 3);
            require(cursor == bytes.data() + bytes.size(), "DER co du lieu thua", 3);
            raw = EVP_PKCS82PKEY(info.get());
        } else {
            raw = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(bytes.size()));
            RsaKey key(raw, EVP_PKEY_free);
            require(bool(key) && cursor == bytes.data() + bytes.size(),
                    "DER phai la SPKI public key va khong du byte", 3);
            require(EVP_PKEY_is_a(key.get(), "RSA") == 1 && EVP_PKEY_get_bits(key.get()) >= 2048,
                    "Phai la RSA >=2048 bit", 3);
            return key;
        }
    }
    RsaKey key(raw, EVP_PKEY_free);
    require(bool(key), "Khong doc duoc khoa PEM/DER", 3);
    require(EVP_PKEY_is_a(key.get(), "RSA") == 1 && EVP_PKEY_get_bits(key.get()) >= 2048,
            "Phai la RSA >=2048 bit", 3);
    return key;
}

void oaepDemoFiles(const string& pubName, const string& privName) {
    auto publicKey = readKey(pubName, false);
    auto privateKey = readKey(privName, true);
    auto nPub = rsaParam(publicKey.get(), OSSL_PKEY_PARAM_RSA_N);
    auto nPriv = rsaParam(privateKey.get(), OSSL_PKEY_PARAM_RSA_N);
    auto ePub = rsaParam(publicKey.get(), OSSL_PKEY_PARAM_RSA_E);
    auto ePriv = rsaParam(privateKey.get(), OSSL_PKEY_PARAM_RSA_E);
    require(BN_cmp(nPub.get(), nPriv.get()) == 0 && BN_cmp(ePub.get(), ePriv.get()) == 0,
            "Khoa cong khai/bi mat khong khop", 4);
    const size_t k = static_cast<size_t>(EVP_PKEY_get_size(publicKey.get()));
    const size_t maxLen = k - 2*32 - 2;
    Bytes msg({'a','t','t','a','c','k',' ','a','t',' ','d','a','w','n'});
    cout << "\n===== OAEP DEMO WITH SAVED KEYS (C-F4) =====\n"
         << "Key bits=" << EVP_PKEY_get_bits(publicKey.get()) << ", k=" << k
         << ", maximum OAEP message=" << maxLen << " bytes\n";
    if (EVP_PKEY_get_bits(publicKey.get()) == 3072)
        cout << "C-T11 RSA-3072 vector: 318 accepted / 319 rejected\n";
    else
        cout << "C-F4 test for this key size; C-T11 separately uses RSA-3072\n";
    auto c1 = opensslEncrypt(publicKey.get(), msg);
    auto c2 = opensslEncrypt(publicKey.get(), msg);
    Bytes p1, p2;
    check("C-T11 twice encrypted -> different ciphertexts", c1 != c2);
    check("C-T11 both decrypt to original", opensslDecrypt(privateKey.get(), c1, p1)
          && opensslDecrypt(privateKey.get(), c2, p2) && p1 == msg && p2 == msg);
    Bytes big(maxLen, 'A'), back;
    auto bigCipher = opensslEncrypt(publicKey.get(), big);
    check("C-T11 max message accepted", opensslDecrypt(privateKey.get(), bigCipher, back) && back == big);
    bool rejected = false;
    rejected = evpRejectsOversizedMessage(publicKey.get(), Bytes(maxLen+1, 'B'));
    check("C-T11 max+1 message rejected", rejected);
    c1[10] ^= 0x01;
    check("C-T11 one bit flipped is rejected", !opensslDecrypt(privateKey.get(),c1,back));
}

void part1ExtraC7() {
    cout << "\n===== C-T7: RANDOM 32-BYTE LEADING ZERO =====\n";
    Bytes data(32);
    require(RAND_bytes(data.data(), static_cast<int>(data.size())) == 1,
            "RAND_bytes that bai");
    data.front() = 0x00;
    auto value = os2ip(data);
    auto recovered = i2osp(value.get(), data.size());
    cout << "Input:     " << toHex(data, 32) << '\n';
    cout << "Recovered: " << toHex(recovered, 32) << '\n';
    check("C-T7 exact 32-byte round-trip including leading zero", recovered == data);
}

// Demo OAEP sử dụng RSA 2048 bit; C-T11 kiểm tra riêng với RSA 3072 bit.
RsaKey newRsaKey3072() {
    RsaContext ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    require(bool(ctx), "Khong tao duoc RSA key context");
    require(EVP_PKEY_keygen_init(ctx.get()) > 0, "RSA keygen init that bai");
    require(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) > 0, "Khong dat duoc 3072 bits");
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_generate(ctx.get(), &raw) > 0 && raw,
            "Khong sinh duoc RSA 3072 bits");
    return RsaKey(raw, EVP_PKEY_free);
}
void part3ExtraC11() {
    cout << "\n===== C-T11: RSA-3072 OAEP-SHA256/MGF1 =====\n";
    auto key = newRsaKey3072();
    const size_t k = static_cast<size_t>(EVP_PKEY_get_size(key.get()));
    const size_t maxLen = k - 2*32 - 2;
    cout << "RSA=" << EVP_PKEY_get_bits(key.get()) << " bits, k=" << k
         << " bytes, maximum=" << maxLen << " bytes\n";
    Bytes message = {'a','t','t','a','c','k',' ','a','t',' ','d','a','w','n'};
    Bytes c1 = opensslEncrypt(key.get(), message), c2 = opensslEncrypt(key.get(), message);
    Bytes r1, r2;
    check("C-T11 randomized: two ciphertexts differ", c1 != c2);
    check("C-T11 both decrypt to original", opensslDecrypt(key.get(), c1, r1)
          && opensslDecrypt(key.get(), c2, r2) && r1 == message && r2 == message);
    Bytes maxMessage(maxLen, 'A');
    Bytes maxCipher = opensslEncrypt(key.get(), maxMessage), restored;
    check("C-T11 318-byte message accepted", maxLen == 318
          && opensslDecrypt(key.get(), maxCipher, restored) && restored == maxMessage);
    bool oversizedRejected = false;
    oversizedRejected = evpRejectsOversizedMessage(key.get(), Bytes(maxLen + 1, 'B'));
    check("C-T11 319-byte message rejected by EVP", oversizedRejected);
    c1[10] ^= 0x01;
    check("C-T11 flipped ciphertext bit rejected", !opensslDecrypt(key.get(), c1, restored));
}

void supplementalTests() {
    part1ExtraC7();
    educationalRawRsa(512);
    part3ExtraC11();
}

void fullTaskC() {
    part1();   // Chuyển đổi OS2IP/I2OSP, C-T1 đến C-T6.
    part2();   // Thử nghiệm các đặc tính của RSA không đệm.
    part3();   // Thử nghiệm OAEP với RSA 2048 bit và giới hạn 190/191 byte.
    supplementalTests();
}


void usage(const string& command = "") {
    if (command == "os2ip") {
        cout << "Usage: task_c_oaep.exe os2ip --hex <even-hex-string> (max 1024 bytes)\n";
    } else if (command == "i2osp") {
        cout << "Usage: task_c_oaep.exe i2osp --int <nonnegative-decimal> --len <0..1024>\n";
    } else if (command == "raw-rsa") {
        cout << "Usage: task_c_oaep.exe raw-rsa --bits <512..1024>\n"
             << "EDUCATIONAL - INSECURE: not for real data\n";
    } else if (command == "oaep-demo") {
        cout << "Usage: task_c_oaep.exe oaep-demo --pub <public.pem/der> --priv <private.pem/der>\n"
             << "C-T11 requires an RSA-3072 key pair; RSA-2048 is also allowed for C-F4.\n";
    } else {
        cout << "Usage:\n"
             << "  task_c_oaep.exe [--all | --all-full | --help]\n"
             << "  task_c_oaep.exe os2ip --hex <even-hex-string>\n"
             << "  task_c_oaep.exe i2osp --int <nonnegative-decimal> --len <0..1024>\n"
             << "  task_c_oaep.exe raw-rsa --bits <512..1024>  [EDUCATIONAL - INSECURE]\n"
             << "  task_c_oaep.exe oaep-demo --pub <public.pem/der> --priv <private.pem/der>\n"
             << "  task_c_oaep.exe <subcommand> --help\n";
    }
}
void summary() {
    cout << "\n===== SUMMARY =====\n";
    cout << "Checks: " << totalChecks << ", passed: " << (totalChecks - failedChecks)
         << ", failed: " << failedChecks << '\n';
    cout << (failedChecks == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED") << '\n';
}
int entry(int argc, char** argv) {
    try {
        // Tùy chọn --all chạy các phép thử của phần thực hành trên lớp với RSA 2048 bit.
        if (argc == 2 && string(argv[1]) == "--all") {
            part1(); part2(); part3(); summary();
            return failedChecks == 0 ? 0 : 5;
        }
        if (argc == 2 && string(argv[1]) == "--all-full") {
            fullTaskC(); summary();
            return failedChecks == 0 ? 0 : 5;
        }
        if (argc == 2 && (string(argv[1]) == "--help" || string(argv[1]) == "help")) {
            usage(); return 0;
        }
        if (argc == 3 && string(argv[2]) == "--help") {
            string command(argv[1]);
            if (command == "os2ip" || command == "i2osp" ||
                command == "raw-rsa" || command == "oaep-demo") {
                usage(command); return 0;
            }
            usage(); return 1;
        }
        if (argc > 1) {
            vector<string> args(argv+1, argv+argc);
            if (args.size() == 3 && args[0] == "os2ip" && args[1] == "--hex") {
                cout << bnDecimal(os2ip(fromHex(args[2])).get()) << '\n';
                return 0;
            }
            if (args.size() == 5 && args[0] == "i2osp" && args[1] == "--int"
                && args[3] == "--len") {
                require(!args[2].empty() && args[2].size() <= 10000 &&
                        args[2].find_first_not_of("0123456789") == string::npos,
                        "--int phai la so nguyen khong am (1..10000 chu so)", 1);
                BIGNUM* number = nullptr;
                int consumed = BN_dec2bn(&number, args[2].c_str());
                Big value(number, BN_clear_free);
                require(value && consumed == static_cast<int>(args[2].size()),
                        "Gia tri decimal khong hop le", 1);
                cout << toHex(i2osp(value.get(), parseSize(args[4], 1024)), 1024) << '\n';
                return 0;
            }
            if (args.size() == 3 && args[0] == "raw-rsa" && args[1] == "--bits") {
                int bits = static_cast<int>(parseSize(args[2], 1024));
                educationalRawRsa(bits); summary();
                return failedChecks == 0 ? 0 : 5;
            }
            if (args.size() == 5 && args[0] == "oaep-demo" && args[1] == "--pub"
                && args[3] == "--priv") {
                oaepDemoFiles(args[2],args[4]); summary();
                return failedChecks == 0 ? 0 : 5;
            }
            usage(); return 1;
        }
        while (true) {
            cout << "\n===== TASK C - RSA/OAEP LAB =====\n"
                 << "1. OS2IP / I2OSP (C-T1..C-T6)\n"
                 << "2. Textbook RSA: determinism and malleability\n"
                 << "3. RSA-OAEP: custom vs OpenSSL, tampering tests\n"
                 << "4. Run ALL tests\n"
                 << "5. Run EXTRA tests (C-T7, C-T10, C-T11)\n"
                 << "0. Exit\nChoice: " << flush;
            string selected;
            if (!getline(cin, selected)) break;
            if (selected == "0") break;
            if (selected == "1") part1();
            else if (selected == "2") part2();
            else if (selected == "3") part3();
            else if (selected == "4") { part1(); part2(); part3(); summary(); }
            else if (selected == "5") { supplementalTests(); summary(); }
            else cout << "Please choose 0..5.\n";
        }
        return failedChecks == 0 ? 0 : 5;
    } catch (const LabError& error) {
        cerr << "[ERROR] " << error.what() << '\n';
        // Không hiển thị chi tiết lỗi đệm OAEP để tránh tiết lộ thông tin nội bộ.
        ERR_clear_error();
        return error.code;
    } catch (const exception& ex) {
        cerr << "[ERROR] Internal failure: " << ex.what() << '\n';
        ERR_clear_error();
        return 5;
    }
}

} // namespace task_c
