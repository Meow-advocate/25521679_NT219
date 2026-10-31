#include "rsa_kem.hpp"
#include "key_io.hpp"
#include "task_cli.hpp"
#include "ossl_raii.hpp"
// Task E
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace task_e {

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;
using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using BN = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BNCtx = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using Kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfCtx = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
using Pkcs8 = std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>;

constexpr std::size_t CHUNK = 64 * 1024;
constexpr std::uint64_t MAX_FILE = std::uint64_t{1} << 30;
constexpr std::size_t KEY_ID_LEN = 32;
constexpr std::size_t AES_KEY_LEN = 32;
constexpr std::size_t NONCE_LEN = 12;
constexpr std::size_t TAG_LEN = 16;
constexpr unsigned char VERSION = 1;
constexpr unsigned char MODE_KEM = 2;
constexpr char LABEL[] = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1";
static_assert(sizeof(LABEL) - 1 == 37, "KDF label must be 37 ASCII bytes");

using LabError = lab::Error;
[[noreturn]] void fail(int code, const std::string& why) { throw LabError(code, why); }
std::string sslError() {
    unsigned long e = ERR_get_error();
    if (!e) return "OpenSSL operation failed";
    char text[256]{};
    ERR_error_string_n(e, text, sizeof(text));
    ERR_clear_error();
    return text;
}
void sslCheck(int ok, const char* operation) {
    if (ok <= 0) fail(5, std::string(operation) + ": " + sslError());
}

// Lưu dữ liệu bí mật và xóa khỏi bộ nhớ khi không còn sử dụng.

struct PlaintextBlock {
    std::array<unsigned char, CHUNK + 16> data{};
    ~PlaintextBlock() { OPENSSL_cleanse(data.data(), data.size()); }
};
bool equalSecret(const SecureBytes& a, const SecureBytes& b) {
    return a.value.size() == b.value.size() &&
           CRYPTO_memcmp(a.value.data(), b.value.data(), a.value.size()) == 0;
}
void require(bool ok, const std::string& why) { if (!ok) fail(5, why); }
// Chỉ nhận khóa RSA từ 2048 bit và có độ dài phù hợp với trường klen.
void checkRsa(EVP_PKEY* k) {
    if (!k || EVP_PKEY_is_a(k, "RSA") != 1 || EVP_PKEY_get_bits(k) < 2048 ||
        EVP_PKEY_get_size(k) <= 0 || EVP_PKEY_get_size(k) > 65535)
        fail(3, "RSA key must be at least 2048 bits and fit the L2PK length field");
}
std::uint64_t fileSize(const fs::path& path) {
    std::error_code ec;
    const auto n = fs::file_size(path, ec);
    if (ec) fail(2, "cannot read file size: " + path.string());
    return static_cast<std::uint64_t>(n);
}
void readExact(std::istream& in, unsigned char* p, std::size_t n) {
    if (n && !in.read(reinterpret_cast<char*>(p), static_cast<std::streamsize>(n)))
        fail(2, "cannot read file");
}
void writeExact(std::ostream& out, const unsigned char* p, std::size_t n) {
    if (n) out.write(reinterpret_cast<const char*>(p), static_cast<std::streamsize>(n));
    if (!out) fail(2, "cannot write file");
}
Bytes readSmall(const fs::path& path, std::size_t limit = 1024 * 1024) {
    auto n = fileSize(path);
    if (n > limit) fail(3, "file exceeds read limit");
    Bytes result(static_cast<std::size_t>(n));
    std::ifstream f(path, std::ios::binary);
    if (!f) fail(2, "cannot open file: " + path.string());
    readExact(f, result.data(), result.size());
    return result;
}
void writeSmall(const fs::path& path, const Bytes& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) fail(2, "cannot create file: " + path.string());
    writeExact(f, bytes.data(), bytes.size());
    f.close();
    if (!f) fail(2, "cannot close file");
}

// Đọc khóa PEM hoặc DER, đồng thời kiểm tra dữ liệu thừa ở cuối tệp.
PKey loadKey(const fs::path& path, bool privatePart) {
    auto key=task_b::loadKey(path,privatePart);
    if(privatePart) task_b::validatePrivate(key.get()); else task_b::validatePublic(key.get());
    return key;
}
BN rsaParam(EVP_PKEY* key, const char* param) {
    BIGNUM* number = nullptr;
    if (EVP_PKEY_get_bn_param(key, param, &number) != 1 || !number)
        fail(5, std::string("cannot obtain RSA parameter: ") + param);
    return BN(number, BN_clear_free);
}
void putU16(Bytes& out, std::size_t n) {
    if (n > 65535) fail(3, "klen does not fit two bytes");
    out.push_back(static_cast<unsigned char>(n >> 8));
    out.push_back(static_cast<unsigned char>(n));
}
void putU64(Bytes& out, std::uint64_t n) {
    for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<unsigned char>(n >> s));
}
std::size_t getU16(const unsigned char* p) {
    return (std::size_t(p[0]) << 8) | p[1];
}
std::uint64_t getU64(const unsigned char* p) {
    std::uint64_t r = 0;
    for (int i = 0; i < 8; ++i) r = (r << 8) | p[i];
    return r;
}

// E-F1, E-F2: Đóng gói và khôi phục bí mật chung bằng RSASVE qua EVP.

Encapsulation encapsulate(EVP_PKEY* recipientPublicKey) {
    checkRsa(recipientPublicKey);
    PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, recipientPublicKey, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) fail(5, "encapsulation context allocation: " + sslError());
    sslCheck(EVP_PKEY_encapsulate_init(ctx.get(), nullptr), "encapsulate init");
    sslCheck(EVP_PKEY_CTX_set_kem_op(ctx.get(), "RSASVE"), "RSASVE operation");
    std::size_t ctSize = 0, zSize = 0;
    sslCheck(EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctSize, nullptr, &zSize), "query encapsulation lengths");
    const auto k = static_cast<std::size_t>(EVP_PKEY_get_size(recipientPublicKey));
    if (ctSize != k || zSize != k) fail(5, "unexpected EVP RSASVE sizes");
    Encapsulation result{Bytes(ctSize), SecureBytes(zSize)};
    sslCheck(EVP_PKEY_encapsulate(ctx.get(), result.kem_ct.data(), &ctSize,
                                   result.shared_secret.value.data(), &zSize), "encapsulate");
    if (ctSize != k || zSize != k) fail(5, "incorrect actual EVP RSASVE sizes");
    return result;
}
// Ckem phải đúng số byte của modulus và thỏa 0 < c < n.
void validateKemCt(EVP_PKEY* priv, const Bytes& ct) {
    checkRsa(priv);
    const auto k = static_cast<std::size_t>(EVP_PKEY_get_size(priv));
    if (ct.size() != k) fail(3, "invalid KEM ciphertext length");
    BN n = rsaParam(priv, OSSL_PKEY_PARAM_RSA_N);
    BN c(BN_bin2bn(ct.data(), static_cast<int>(ct.size()), nullptr), BN_clear_free);
    if (!c) fail(5, "cannot parse KEM ciphertext integer");
    if (BN_is_negative(c.get()) || BN_is_zero(c.get()) || BN_cmp(c.get(), n.get()) >= 0)
        fail(3, "KEM ciphertext integer out of range");
}
SecureBytes decapsulate(EVP_PKEY* recipientPrivateKey, const Bytes& kem_ct) {
    validateKemCt(recipientPrivateKey, kem_ct);  // Kiểm tra giá trị Ckem trước khi giải mã và dẫn xuất khóa.
    PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, recipientPrivateKey, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) fail(5, "decapsulation context allocation: " + sslError());
    sslCheck(EVP_PKEY_decapsulate_init(ctx.get(), nullptr), "decapsulate init");
    sslCheck(EVP_PKEY_CTX_set_kem_op(ctx.get(), "RSASVE"), "RSASVE decapsulation op");
    std::size_t zSize = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &zSize, kem_ct.data(), kem_ct.size()) <= 0) {
        ERR_clear_error(); fail(4, "decryption failed");
    }
    const auto k = static_cast<std::size_t>(EVP_PKEY_get_size(recipientPrivateKey));
    if (zSize != k) fail(5, "unexpected RSASVE shared secret size");
    SecureBytes secret(zSize);
    if (EVP_PKEY_decapsulate(ctx.get(), secret.value.data(), &zSize, kem_ct.data(), kem_ct.size()) <= 0) {
        ERR_clear_error(); fail(4, "decryption failed");
    }
    if (zSize != k) fail(4, "decryption failed");
    return secret;
}

// E-F3: Cách tính RSASVE bằng BIGNUM để đối chiếu với EVP trong kiểm thử.
namespace edu {
Encapsulation rsasveEncapsulate(EVP_PKEY* recipientPublicKey) {
    checkRsa(recipientPublicKey);
    BN n = rsaParam(recipientPublicKey, OSSL_PKEY_PARAM_RSA_N);
    BN e = rsaParam(recipientPublicKey, OSSL_PKEY_PARAM_RSA_E);
    BN bound(BN_dup(n.get()), BN_clear_free);
    BN z(BN_new(), BN_clear_free);
    BN c(BN_new(), BN_clear_free);
    BNCtx ctx(BN_CTX_new(), BN_CTX_free);
    if (!bound || !z || !c || !ctx) fail(5, "BIGNUM allocation failed");
    sslCheck(BN_sub_word(bound.get(), 3), "n minus 3");
    sslCheck(BN_rand_range(z.get(), bound.get()), "BN_rand_range");
    sslCheck(BN_add_word(z.get(), 2), "z plus 2");
    sslCheck(BN_mod_exp(c.get(), z.get(), e.get(), n.get(), ctx.get()), "educational modular exp");
    const int k = EVP_PKEY_get_size(recipientPublicKey);
    Encapsulation enc{Bytes(static_cast<std::size_t>(k)), SecureBytes(static_cast<std::size_t>(k))};
    if (BN_bn2binpad(c.get(), enc.kem_ct.data(), k) != k ||
        BN_bn2binpad(z.get(), enc.shared_secret.value.data(), k) != k)
        fail(5, "educational I2OSP failed");
    return enc;
}
SecureBytes rsasveDecapsulate(EVP_PKEY* recipientPrivateKey, const Bytes& kem_ct) {
    validateKemCt(recipientPrivateKey, kem_ct);
    BN n = rsaParam(recipientPrivateKey, OSSL_PKEY_PARAM_RSA_N);
    BN d = rsaParam(recipientPrivateKey, OSSL_PKEY_PARAM_RSA_D);
    BN c(BN_bin2bn(kem_ct.data(), static_cast<int>(kem_ct.size()), nullptr), BN_clear_free);
    BN z(BN_new(), BN_clear_free);
    BNCtx ctx(BN_CTX_new(), BN_CTX_free);
    if (!n || !d || !c || !z || !ctx) fail(5, "BIGNUM allocation failed");
    sslCheck(BN_mod_exp(z.get(), c.get(), d.get(), n.get(), ctx.get()), "educational decrypt mod exp");
    const int k = EVP_PKEY_get_size(recipientPrivateKey);
    SecureBytes result(static_cast<std::size_t>(k));
    if (BN_bn2binpad(z.get(), result.value.data(), k) != k) fail(5, "educational I2OSP failed");
    return result;
}
}  // Kết thúc phần tính toán bằng BIGNUM

// Tính key_id bằng SHA-256 của khóa công khai ở dạng SPKI DER.
Bytes keyId(EVP_PKEY* key) {
    checkRsa(key);
    const int n = i2d_PUBKEY(key, nullptr);
    if (n <= 0) fail(5, "cannot encode SPKI DER");
    Bytes spki(static_cast<std::size_t>(n));
    unsigned char* p = spki.data();
    if (i2d_PUBKEY(key, &p) != n) fail(5, "SPKI DER output error");
    Bytes id(KEY_ID_LEN);
    unsigned int digestSize = 0;
    sslCheck(EVP_Digest(spki.data(), spki.size(), id.data(), &digestSize, EVP_sha256(), nullptr),
             "SHA256(SPKI DER)");
    if (digestSize != KEY_ID_LEN) fail(5, "unexpected SHA256 digest length");
    return id;
}

// E-F4: Dẫn xuất khóa bằng HKDF-SHA256. Salt rỗng được xử lý theo RFC 5869.
SecureBytes hkdf(const Bytes& ikm, const Bytes& salt, const Bytes& info, std::size_t n) {
    Kdf algorithm(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    if (!algorithm) fail(5, "HKDF algorithm not found");
    KdfCtx ctx(EVP_KDF_CTX_new(algorithm.get()), EVP_KDF_CTX_free);
    if (!ctx) fail(5, "HKDF context allocation failed");
    char digest[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    const unsigned char empty = 0;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            const_cast<unsigned char*>(ikm.empty() ? &empty : ikm.data()), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            const_cast<unsigned char*>(salt.empty() ? &empty : salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            const_cast<unsigned char*>(info.empty() ? &empty : info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };
    SecureBytes output(n);
    sslCheck(EVP_KDF_derive(ctx.get(), output.value.data(), output.value.size(), parameters),
             "HKDF derive");
    return output;
}
// Ghép nhãn, key_id, độ dài Ckem và Ckem vào trường info của HKDF.
SecureBytes deriveWithLabel(const SecureBytes& Z, const Bytes& keyIdBytes,
                            const Bytes& kemCt, const std::string& label) {
    if (keyIdBytes.size() != KEY_ID_LEN || Z.value.empty() || Z.value.size() != kemCt.size())
        fail(3, "invalid HKDF context lengths");
    if (kemCt.size() > 65535) fail(3, "KEM ciphertext too long for HKDF context");
    Bytes info(label.begin(), label.end());
    info.push_back(0x00);
    info.insert(info.end(), keyIdBytes.begin(), keyIdBytes.end());
    putU16(info, kemCt.size());
    info.insert(info.end(), kemCt.begin(), kemCt.end());
    return hkdf(Z.value, {}, info, AES_KEY_LEN);
}
SecureBytes deriveAesKey(const SecureBytes& Z, const Bytes& keyIdBytes, const Bytes& kemCt) {
    return deriveWithLabel(Z, keyIdBytes, kemCt, LABEL);
}

// Gói L2PK chế độ 0x02 gồm phần đầu, Ckem, key_id, nonce, độ dài, bản mã và tag.
// Ghi kết quả vào tệp .part; chỉ đổi tên sau khi xử lý thành công.
class PendingOutput {
    fs::path dest_, part_;
    bool committed_ = false;
    bool force_;
public:
    PendingOutput(const fs::path& path, bool force) : dest_(path), part_(path.string() + ".part"), force_(force) {
        std::error_code ec;
        if (fs::exists(dest_, ec) && !force_) fail(2, "output exists (use --force)");
        if (fs::exists(part_, ec)) fail(2, "temporary .part already exists");
    }
    const fs::path& part() const { return part_; }
    void commit() {
        std::error_code ec;
        if (force_ && fs::exists(dest_, ec)) {
            fs::remove(dest_, ec);
            if (ec) fail(2, "cannot replace existing output");
        }
        fs::rename(part_, dest_, ec);
        if (ec) fail(2, "cannot finalize output: " + ec.message());
        committed_ = true;
    }
    ~PendingOutput() {
        if (!committed_) { std::error_code ignored; fs::remove(part_, ignored); }
    }
};
void rejectSameFile(const fs::path& a, const fs::path& b) {
    std::error_code ec;
    if (fs::exists(b, ec) && fs::equivalent(a, b, ec) && !ec)
        fail(1, "input and output must differ");
    if (fs::absolute(a).lexically_normal() == fs::absolute(b).lexically_normal())
        fail(1, "input and output must differ");
}

// Đóng gói Ckem và dùng khóa dẫn xuất từ Z để mã hóa dữ liệu bằng AES-GCM.
std::size_t kemEncrypt(EVP_PKEY* pub, const fs::path& input,
                       const fs::path& output, bool force = false) {
    checkRsa(pub);
    rejectSameFile(input, output);
    const std::uint64_t plainLen = fileSize(input);
    if (plainLen > MAX_FILE) fail(3, "input exceeds 1 GiB limit");
    std::ifstream in(input, std::ios::binary);
    if (!in) fail(2, "cannot open input");
    PendingOutput target(output, force);
    rejectSameFile(input, target.part());

    Encapsulation enc = encapsulate(pub);
    Bytes id = keyId(pub);
    SecureBytes aes = deriveAesKey(enc.shared_secret, id, enc.kem_ct);
    std::array<unsigned char, NONCE_LEN> nonce{};
    sslCheck(RAND_bytes(nonce.data(), static_cast<int>(nonce.size())), "nonce RNG");
    Bytes header{'L', '2', 'P', 'K', VERSION, MODE_KEM, 0, 0};
    putU16(header, enc.kem_ct.size());
    header.insert(header.end(), enc.kem_ct.begin(), enc.kem_ct.end());
    header.insert(header.end(), id.begin(), id.end());
    header.insert(header.end(), nonce.begin(), nonce.end());
    putU64(header, plainLen);
    if (header.size() != 62 + enc.kem_ct.size()) fail(5, "invalid header construction");

    std::ofstream out(target.part(), std::ios::binary | std::ios::trunc);
    if (!out) fail(2, "cannot create output .part");
    writeExact(out, header.data(), header.size());
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) fail(5, "cannot create AES-GCM cipher context");
    sslCheck(EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(),
                                  aes.value.data(), nonce.data(), nullptr), "AES-GCM encrypt init");
    int produced = 0;
    sslCheck(EVP_EncryptUpdate(ctx.get(), nullptr, &produced, header.data(),
                                static_cast<int>(header.size())), "AES-GCM header AAD");
    std::array<unsigned char, CHUNK> src{};
    std::array<unsigned char, CHUNK + 16> dst{};
    for (std::uint64_t remain = plainLen; remain > 0;) {
        auto block = static_cast<std::size_t>(std::min<std::uint64_t>(CHUNK, remain));
        readExact(in, src.data(), block);
        sslCheck(EVP_EncryptUpdate(ctx.get(), dst.data(), &produced, src.data(), static_cast<int>(block)),
                 "AES-GCM encrypt chunk");
        writeExact(out, dst.data(), static_cast<std::size_t>(produced));
        remain -= block;
    }
    sslCheck(EVP_EncryptFinal_ex(ctx.get(), dst.data(), &produced), "AES-GCM encrypt final");
    writeExact(out, dst.data(), static_cast<std::size_t>(produced));
    std::array<unsigned char, TAG_LEN> tag{};
    sslCheck(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                                  static_cast<int>(TAG_LEN), tag.data()), "AES-GCM get tag");
    writeExact(out, tag.data(), tag.size());
    out.close();
    if (!out) fail(2, "cannot close encrypted file");
    target.commit();
    return header.size();
}

struct Package {
    Bytes header;
    Bytes kemCt;
    Bytes id;
    std::array<unsigned char, NONCE_LEN> nonce{};
    std::uint64_t ctLen = 0;
};
// Kiểm tra cấu trúc gói tin và các trường độ dài trước khi giải mã.
Package parsePackage(std::ifstream& in, std::uint64_t size, EVP_PKEY* priv) {
    checkRsa(priv);
    if (size < 62 + TAG_LEN) fail(3, "truncated package");
    std::array<unsigned char, 10> first{};
    readExact(in, first.data(), first.size());
    if (std::memcmp(first.data(), "L2PK", 4) != 0) fail(3, "bad package magic");
    if (first[4] != VERSION) fail(3, "unsupported package version");
    if (first[5] != MODE_KEM) fail(3, "unexpected package mode (expected KEM 0x02)");
    if (first[6] != 0 || first[7] != 0) fail(3, "reserved bytes must be zero");
    const std::size_t k = static_cast<std::size_t>(EVP_PKEY_get_size(priv));
    const std::size_t klen = getU16(first.data() + 8);
    if (klen != k) fail(3, "klen does not match RSA modulus size");
    const std::size_t headerSize = 62 + k;
    if (size < static_cast<std::uint64_t>(headerSize + TAG_LEN)) fail(3, "truncated package");
    Package p;
    p.header.assign(first.begin(), first.end());
    p.header.resize(headerSize);
    readExact(in, p.header.data() + first.size(), headerSize - first.size());
    const auto* ptr = p.header.data();
    p.ctLen = getU64(ptr + 54 + k);
    if (p.ctLen > MAX_FILE) fail(3, "ciphertext length exceeds 1 GiB limit");
    if (size != static_cast<std::uint64_t>(headerSize) + p.ctLen + TAG_LEN)
        fail(3, "package total length mismatch");
    p.kemCt.assign(ptr + 10, ptr + 10 + k);
    p.id.assign(ptr + 10 + k, ptr + 42 + k);
    std::copy_n(ptr + 42 + k, NONCE_LEN, p.nonce.begin());
    // Nếu key_id không khớp, trả lỗi 4 để không tiết lộ thông tin về khóa nhận.
    Bytes expectedId = keyId(priv);
    if (CRYPTO_memcmp(p.id.data(), expectedId.data(), KEY_ID_LEN) != 0)
        fail(4, "decryption failed");
    validateKemCt(priv, p.kemCt);  // Kiểm tra Ckem trước HKDF; dữ liệu sai trả mã 3.
    return p;
}
// Chỉ công bố bản rõ sau khi kiểm tra GCM tag thành công.
std::size_t kemDecrypt(EVP_PKEY* priv, const fs::path& input,
                       const fs::path& output, bool force = false) {
    checkRsa(priv);
    rejectSameFile(input, output);
    const auto size = fileSize(input);
    std::ifstream in(input, std::ios::binary);
    if (!in) fail(2, "cannot open package");
    Package package = parsePackage(in, size, priv);
    PendingOutput target(output, force);
    rejectSameFile(input, target.part());
    SecureBytes Z = decapsulate(priv, package.kemCt);
    SecureBytes aes = deriveAesKey(Z, package.id, package.kemCt);
    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) fail(5, "cannot create AES-GCM decrypt context");
    sslCheck(EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_gcm(),
                                  aes.value.data(), package.nonce.data(), nullptr), "AES-GCM decrypt init");
    int produced = 0;
    sslCheck(EVP_DecryptUpdate(ctx.get(), nullptr, &produced,
                                package.header.data(), static_cast<int>(package.header.size())),
             "AES-GCM header AAD");
    std::ofstream out(target.part(), std::ios::binary | std::ios::trunc);
    if (!out) fail(2, "cannot create output .part");
    std::array<unsigned char, CHUNK> src{};
    PlaintextBlock dst;
    for (std::uint64_t remain = package.ctLen; remain > 0;) {
        auto block = static_cast<std::size_t>(std::min<std::uint64_t>(CHUNK, remain));
        readExact(in, src.data(), block);
        sslCheck(EVP_DecryptUpdate(ctx.get(), dst.data.data(), &produced, src.data(), static_cast<int>(block)),
                 "AES-GCM decrypt chunk");
        writeExact(out, dst.data.data(), static_cast<std::size_t>(produced));
        remain -= block;
    }
    std::array<unsigned char, TAG_LEN> tag{};
    readExact(in, tag.data(), tag.size());
    sslCheck(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                                  static_cast<int>(TAG_LEN), tag.data()), "AES-GCM set tag");
    if (EVP_DecryptFinal_ex(ctx.get(), dst.data.data(), &produced) != 1) {
        ERR_clear_error();
        out.close();
        fail(4, "decryption failed");
    }
    writeExact(out, dst.data.data(), static_cast<std::size_t>(produced));
    out.close();
    if (!out) fail(2, "cannot close decrypted file");
    target.commit();
    return package.header.size();
}

Bytes fromHex(const char* text) {
    std::string s(text);
    if (s.size() % 2) fail(5, "invalid test hex");
    Bytes out;
    for (std::size_t i = 0; i < s.size(); i += 2) {
        const std::string two = s.substr(i, 2);
        out.push_back(static_cast<unsigned char>(std::stoul(two, nullptr, 16)));
    }
    return out;
}
Bytes hexRange(unsigned char start, std::size_t n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<unsigned char>(start + i);
    return b;
}

// Tạo thư mục tạm cho các bài kiểm thử và tự xóa khi kết thúc.
class TestDir {
    fs::path dir_;
public:
    TestDir() {
        auto base = fs::temp_directory_path();
        for (int attempts = 0; attempts < 16; ++attempts) {
            std::array<unsigned char, 12> r{};
            sslCheck(RAND_bytes(r.data(), static_cast<int>(r.size())), "test dir RNG");
            const char* hex = "0123456789abcdef";
            std::string suffix;
            for (auto v : r) { suffix.push_back(hex[v >> 4]); suffix.push_back(hex[v & 15]); }
            dir_ = base / ("lab03_task_e_" + suffix);
            std::error_code ec;
            if (fs::create_directory(dir_, ec)) return;
            if (ec && ec != std::errc::file_exists) fail(2, "cannot create temporary test directory");
        }
        fail(2, "cannot obtain unique temporary test directory");
    }
    fs::path file(const std::string& filename) const { return dir_ / filename; }
    ~TestDir() { std::error_code ec; fs::remove_all(dir_, ec); }
};
// Xuất khóa PEM/DER tạm thời để thử các định dạng đầu vào.
void saveDerPublic(const fs::path& path, EVP_PKEY* key) {
    int len = i2d_PUBKEY(key, nullptr);
    if (len <= 0) fail(5, "cannot DER encode public key");
    Bytes raw(static_cast<std::size_t>(len));
    unsigned char* p = raw.data();
    if (i2d_PUBKEY(key, &p) != len) fail(5, "DER public key encoding failed");
    writeSmall(path, raw);
}
void saveDerPrivate(const fs::path& path, EVP_PKEY* key) {
    Pkcs8 p8(EVP_PKEY2PKCS8(key), PKCS8_PRIV_KEY_INFO_free);
    if (!p8) fail(5, "cannot PKCS#8 encode private key");
    const int len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
    if (len <= 0) fail(5, "cannot DER encode PKCS#8");
    Bytes raw(static_cast<std::size_t>(len));
    struct Clean { Bytes& b; ~Clean() { if (!b.empty()) OPENSSL_cleanse(b.data(), b.size()); } } clean{raw};
    unsigned char* p = raw.data();
    if (i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &p) != len) fail(5, "DER PKCS#8 encoding failed");
    writeSmall(path, raw);
}
void savePemPublic(const fs::path& path, EVP_PKEY* key) {
    Bio bio(BIO_new_file(path.string().c_str(), "wb"), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key) != 1) fail(5, "cannot write test public PEM");
}
void savePemPrivate(const fs::path& path, EVP_PKEY* key) {
    Bio bio(BIO_new_file(path.string().c_str(), "wb"), BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        fail(5, "cannot write test private PEM");
}

// Kiểm tra mã lỗi và bảo đảm không còn tệp kết quả hoặc tệp .part.
bool expectedDecryptFailure(EVP_PKEY* priv, const fs::path& pkg,
                            const fs::path& output, int code) {
    std::error_code ec;
    fs::remove(output, ec);
    fs::remove(fs::path(output.string() + ".part"), ec);
    bool matched = false;
    try { (void)kemDecrypt(priv, pkg, output); }
    catch (const LabError& e) {
        matched = e.code == code && (code != 4 || std::string(e.what()) == "decryption failed");
    }
    return matched && !fs::exists(output) && !fs::exists(fs::path(output.string() + ".part"));
}

// E-F6: Chạy lần lượt các kiểm thử E-T1 đến E-T9.
int selfTest(EVP_PKEY* pub, EVP_PKEY* priv) {
    checkRsa(pub); checkRsa(priv);
    if (EVP_PKEY_get_size(pub) != EVP_PKEY_get_size(priv) || keyId(pub) != keyId(priv))
        fail(3, "selftest public and private keys do not match");
    std::cout << "=== TASK E COMPLETE SELFTEST ===\n";
    std::cout << "Linked OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << '\n';
    std::cout << "RSA modulus: " << EVP_PKEY_get_bits(pub) << " bits\n";
    int passed = 0;
    const auto check = [&](const char* label, bool ok) {
        std::cout << label << ": " << (ok ? "PASS" : "FAIL") << '\n';
        if (ok) ++passed;
    };

    // E-T1: Thực hiện 100 lần đóng gói, kiểm tra bí mật chung và Ckem không trùng.
    std::set<Bytes> distinct;
    bool all100 = true;
    for (int i = 0; i < 100; ++i) {
        Encapsulation e = encapsulate(pub);
        SecureBytes z = decapsulate(priv, e.kem_ct);
        all100 = all100 && equalSecret(e.shared_secret, z);
        distinct.insert(e.kem_ct);
    }
    check("E-T1 EVP 100 rounds / 100 distinct Ckem", all100 && distinct.size() == 100);

    Encapsulation eduEnc = edu::rsasveEncapsulate(pub);
    SecureBytes byEvp = decapsulate(priv, eduEnc.kem_ct);
    Encapsulation evpEnc = encapsulate(pub);
    SecureBytes byEdu = edu::rsasveDecapsulate(priv, evpEnc.kem_ct);
    check("E-T2 EDU->EVP and EVP->EDU", equalSecret(eduEnc.shared_secret, byEvp) &&
                                        equalSecret(evpEnc.shared_secret, byEdu));

    // E-T3: Đối chiếu kết quả HKDF với bộ dữ liệu mẫu số 1 của RFC 5869.
    Bytes ikm(22, 0x0b);
    Bytes salt = hexRange(0x00, 13);
    Bytes info = hexRange(0xf0, 10);
    const Bytes kat = fromHex("3cb25f25faacd57a90434f64d0362f2a"
                              "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                              "34007208d5b887185865");
    SecureBytes actual = hkdf(ikm, salt, info, 42);
    check("E-T3 RFC5869 SHA256 KAT", actual.value.size() == kat.size() &&
          CRYPTO_memcmp(actual.value.data(), kat.data(), kat.size()) == 0);

    Bytes id = keyId(pub);
    SecureBytes k1 = deriveAesKey(evpEnc.shared_secret, id, evpEnc.kem_ct);
    std::string alteredLabel(LABEL);
    alteredLabel[0] ^= 0x01;
    SecureBytes k2 = deriveWithLabel(evpEnc.shared_secret, id, evpEnc.kem_ct, alteredLabel);
    check("E-T4 one-bit KDF label change", !equalSecret(k1, k2));

    TestDir t;
    const fs::path plain = t.file("sample.bin");
    const Bytes sample = Bytes{'L','a','b','0','3',0,0xff,'E','-','T','5','\n'};
    writeSmall(plain, sample);
    const fs::path pemPub = t.file("public.pem"), pemPriv = t.file("private.pem");
    const fs::path derPub = t.file("public.der"), derPriv = t.file("private.der");
    savePemPublic(pemPub, pub); savePemPrivate(pemPriv, priv);
    saveDerPublic(derPub, pub); saveDerPrivate(derPriv, priv);
    bool matrixOk = true;
    const std::array<fs::path, 4> pubs{pemPub, derPub, pemPub, derPub};
    const std::array<fs::path, 4> privs{pemPriv, derPriv, derPriv, pemPriv};
    for (std::size_t i = 0; i < 4; ++i) {
        PKey p = loadKey(pubs[i], false);
        PKey s = loadKey(privs[i], true);
        auto package = t.file("test_package_" + std::to_string(i) + ".l2pk");
        auto recovered = t.file("test_recovered_" + std::to_string(i) + ".bin");
        kemEncrypt(p.get(), plain, package);
        kemDecrypt(s.get(), package, recovered);
        matrixOk = matrixOk && readSmall(recovered) == sample;
    }
    check("E-T5 PEM/DER 4-way file round trip", matrixOk);

    const fs::path good = t.file("good.l2pk"), broken = t.file("broken.l2pk"),
                   rejected = t.file("rejected.bin");
    kemEncrypt(pub, plain, good);
    Bytes raw = readSmall(good);
    const std::size_t k = static_cast<std::size_t>(EVP_PKEY_get_size(pub));
    const auto testModified = [&](const Bytes& changed, int expectedCode) {
        writeSmall(broken, changed);
        return expectedDecryptFailure(priv, broken, rejected, expectedCode);
    };
    // E-T6: Kiểm tra klen sai, Ckem bằng n hoặc bằng 0; đều phải trả mã 3.
    Bytes wrongLen = raw;
    wrongLen[9] ^= 1;
    bool t6 = testModified(wrongLen, 3);
    BN n = rsaParam(pub, OSSL_PKEY_PARAM_RSA_N);
    Bytes modulus(k);
    require(BN_bn2binpad(n.get(), modulus.data(), static_cast<int>(k)) == static_cast<int>(k),
            "cannot encode RSA modulus for E-T6");
    Bytes tooLarge = raw;
    std::copy(modulus.begin(), modulus.end(), tooLarge.begin() + 10);
    t6 = t6 && testModified(tooLarge, 3);
    Bytes zero = raw;
    std::fill(zero.begin() + 10, zero.begin() + 10 + static_cast<std::ptrdiff_t>(k), 0);
    t6 = t6 && testModified(zero, 3);
    check("E-T6 invalid kem_ct length / >=n / zero", t6);

    // E-T7: Đảo một bit của Ckem nhưng vẫn giữ giá trị trong khoảng hợp lệ.
    // Khi Z thay đổi, bước xác thực GCM phải thất bại và không tạo bản rõ.
    Bytes altered = raw;
    altered[10 + k - 1] ^= 1;
    Bytes alteredCt(altered.begin() + 10, altered.begin() + 10 + static_cast<std::ptrdiff_t>(k));
    bool stillInRange = true;
    try { validateKemCt(priv, alteredCt); }
    catch (const LabError&) { stillInRange = false; }
    bool t7 = false;
    if (stillInRange) {
        Bytes goodCt(raw.begin() + 10, raw.begin() + 10 + static_cast<std::ptrdiff_t>(k));
        SecureBytes zGood = decapsulate(priv, goodCt);
        SecureBytes zTampered = decapsulate(priv, alteredCt);
        t7 = !equalSecret(zGood, zTampered) && testModified(altered, 4);
    }
    check("E-T7 modified KEM changes Z; GCM rejects", t7);

    // E-T8: Lần lượt đảo một bit ở key_id, nonce, ciphertext và tag.
    bool t8 = true;
    for (auto offset : {10 + k, 42 + k, 62 + k, raw.size() - 1}) {
        Bytes changed = raw;
        changed[offset] ^= 1;
        // Sai key_id trả mã 4; các trường còn lại bị GCM phát hiện.
        t8 = t8 && testModified(changed, 4);
    }
    check("E-T8 tampered key_id / nonce / ciphertext / tag", t8);

    // E-T9: Thử sai khóa RSA, sai mode và phiên bản không được hỗ trợ.
    PKey other(EVP_RSA_gen(EVP_PKEY_get_bits(priv)), EVP_PKEY_free);
    if (!other) fail(5, "cannot make second RSA key");
    bool t9 = expectedDecryptFailure(other.get(), good, rejected, 4);
    Bytes wrongMode = raw;
    wrongMode[5] = 1;
    t9 = t9 && testModified(wrongMode, 3);
    Bytes wrongVersion = raw;
    wrongVersion[4] = 2;
    t9 = t9 && testModified(wrongVersion, 3);
    check("E-T9 wrong key / mode 0x01 / version 0x02", t9);

    std::cout << "Task E total: " << passed << "/9 PASS\n";
    std::cout << "No shared secrets or AES keys were printed.\n";
    return passed == 9 ? 0 : 5;
}

struct Cli {
    fs::path pub, priv, input, output;
    bool force = false;
};
Cli parseCli(int argc, char** argv, bool test, bool encrypt) {
    Cli args;
    bool hasPub = false, hasPriv = false, hasIn = false, hasOut = false;
    for (int i = 2; i < argc; ++i) {
        std::string option(argv[i]);
        if (option == "--force") {
            if (test || args.force) fail(1, "invalid/duplicate --force");
            args.force = true;
        } else if (option == "--pub" && (test || encrypt)) {
            if (hasPub || i + 1 >= argc) fail(1, "invalid --pub");
            args.pub = argv[++i]; hasPub = true;
        } else if (option == "--priv" && (test || !encrypt)) {
            if (hasPriv || i + 1 >= argc) fail(1, "invalid --priv");
            args.priv = argv[++i]; hasPriv = true;
        } else if (!test && option == "--in") {
            if (hasIn || i + 1 >= argc) fail(1, "invalid --in");
            args.input = argv[++i]; hasIn = true;
        } else if (!test && option == "--out") {
            if (hasOut || i + 1 >= argc) fail(1, "invalid --out");
            args.output = argv[++i]; hasOut = true;
        } else fail(1, "unknown or unsupported argument: " + option);
    }
    if (test) { if (!hasPub || !hasPriv) fail(1, "kem-selftest requires --pub and --priv"); }
    else if (!(hasIn && hasOut && (encrypt ? hasPub : hasPriv)))
        fail(1, "missing --pub/--priv, --in or --out");
    return args;
}
void usage() {
    std::cout << "Task E - RSASVE/HKDF/AES-256-GCM (lab profile, not RFC 9690)\n"
              << "  task_e_kem.exe kem-selftest --pub <key> --priv <key>\n"
              << "  task_e_kem.exe kem-encrypt --pub <key> --in <file> --out <l2pk> [--force]\n"
              << "  task_e_kem.exe kem-decrypt --priv <key> --in <l2pk> --out <file> [--force]\n"
              << "  task_e_kem.exe <public.pem> <private.pem>  (shortcut for selftest)\n";
}


int entry(int argc, char** argv) {
    try {
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "help")) {
            usage(); return 0;
        }
        if (argc == 3 && argv[1][0] != '-') {
            PKey pub = loadKey(argv[1], false);
            PKey priv = loadKey(argv[2], true);
            return selfTest(pub.get(), priv.get());
        }
        if (argc < 2) { usage(); return 1; }
        std::string sub(argv[1]);
        if (sub == "kem-selftest") {
            Cli a = parseCli(argc, argv, true, false);
            PKey pub = loadKey(a.pub, false), priv = loadKey(a.priv, true);
            return selfTest(pub.get(), priv.get());
        }
        if (sub == "kem-encrypt") {
            Cli a = parseCli(argc, argv, false, true);
            PKey pub = loadKey(a.pub, false);
            auto header = kemEncrypt(pub.get(), a.input, a.output, a.force);
            std::cout << "ENCRYPT OK | mode=0x02 | header=" << header << " bytes\n";
            return 0;
        }
        if (sub == "kem-decrypt") {
            Cli a = parseCli(argc, argv, false, false);
            PKey priv = loadKey(a.priv, true);
            auto header = kemDecrypt(priv.get(), a.input, a.output, a.force);
            std::cout << "DECRYPT OK | mode=0x02 | header=" << header << " bytes\n";
            return 0;
        }
        usage(); return 1;
    } catch (const LabError& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return e.code;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 5;
    }
}

} // namespace task_e
