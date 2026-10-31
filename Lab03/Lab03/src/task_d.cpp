#include "key_io.hpp"
#include "task_cli.hpp"
#include "ossl_raii.hpp"
// Lab 3 - Task D: RSA-OAEP-SHA256 + AES-256-GCM.
// Một tệp nguồn cho phần thực hành; các lệnh encrypt/decrypt dùng lại khi tích hợp lab03.
// Biên dịch với C++17 và libcrypto (OpenSSL 3.x hoặc phiên bản tương thích).
// Không in khóa AES, khóa bí mật RSA hoặc dữ liệu giải mã chưa xác thực.

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
#include <stdexcept>
#include <string>
#include <vector>

namespace task_d {

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

namespace {
constexpr std::size_t BLOCK = 64 * 1024;
constexpr std::uint64_t MAX_FILE = std::uint64_t{1} << 30;  // 1 GiB.
constexpr std::size_t AES_KEY_LEN = 32;
constexpr std::size_t NONCE_LEN = 12;
constexpr std::size_t TAG_LEN = 16;
constexpr unsigned char VERSION = 0x01;
constexpr unsigned char MODE_OAEP = 0x01;

using LabError = lab::Error;

[[noreturn]] void fail(int code, const std::string& detail) { throw LabError(code, detail); }

std::string opensslError() {
    const unsigned long e = ERR_get_error();
    if (!e) return "OpenSSL returned failure";
    char buf[256]{};
    ERR_error_string_n(e, buf, sizeof(buf));
    while (ERR_get_error() != 0) {}  // Xóa các lỗi còn lại.
    return buf;
}

void sslCheck(int result, const std::string& operation) {
    if (result <= 0) fail(5, operation + ": " + opensslError());
}

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

struct SecureKey {
    std::array<unsigned char, AES_KEY_LEN> data{};
    ~SecureKey() { OPENSSL_cleanse(data.data(), data.size()); }
    SecureKey() = default;
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;
};

struct SecureChunk {
    std::array<unsigned char, BLOCK + 16> data{};
    ~SecureChunk() { OPENSSL_cleanse(data.data(), data.size()); }
};

std::uint64_t lengthOf(const fs::path& path) {
    std::error_code ec;
    const auto n = fs::file_size(path, ec);
    if (ec) fail(2, "cannot read input file size: " + path.string());
    return static_cast<std::uint64_t>(n);
}

void readExact(std::istream& f, unsigned char* dest, std::size_t n) {
    if (n == 0) return;
    if (!f.read(reinterpret_cast<char*>(dest), static_cast<std::streamsize>(n)))
        fail(2, "cannot read input file");
}

void writeExact(std::ostream& f, const unsigned char* data, std::size_t n) {
    if (n == 0) return;
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
    if (!f) fail(2, "cannot write output file");
}

Bytes readSmallFile(const fs::path& path, std::size_t limit) {
    const auto size = lengthOf(path);
    if (size > limit) fail(3, "file is too large");
    std::ifstream f(path, std::ios::binary);
    if (!f) fail(2, "cannot open input file: " + path.string());
    Bytes bytes(static_cast<std::size_t>(size));
    readExact(f, bytes.data(), bytes.size());
    return bytes;
}

void writeSmallFile(const fs::path& path, const Bytes& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) fail(2, "cannot open output file: " + path.string());
    writeExact(f, bytes.data(), bytes.size());
    f.close();
    if (!f) fail(2, "cannot close output file");
}

// Hỗ trợ PEM và DER, kiểm tra cả phần dữ liệu thừa sau khóa DER/PEM.
PKey loadKey(const fs::path& path, bool privatePart) {
    auto key=task_b::loadKey(path,privatePart);
    if(privatePart) task_b::validatePrivate(key.get()); else task_b::validatePublic(key.get());
    return key;
}

void checkRsaKey(EVP_PKEY* key) {
    if (!key || EVP_PKEY_is_a(key, "RSA") != 1 || EVP_PKEY_get_bits(key) < 2048)
        fail(3, "RSA key must have at least 2048 bits");
}

void configureOaep(EVP_PKEY_CTX* ctx) {
    sslCheck(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "OAEP padding");
    sslCheck(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()), "OAEP SHA-256");
    sslCheck(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()), "MGF1 SHA-256");
}

Bytes wrapKey(EVP_PKEY* pub, const SecureKey& aes) {
    PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pub, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) fail(5, "cannot create RSA context: " + opensslError());
    sslCheck(EVP_PKEY_encrypt_init(ctx.get()), "RSA encrypt init");
    configureOaep(ctx.get());
    std::size_t n = 0;
    sslCheck(EVP_PKEY_encrypt(ctx.get(), nullptr, &n, aes.data.data(), aes.data.size()),
             "RSA wrapped key length");
    Bytes wrapped(n);
    sslCheck(EVP_PKEY_encrypt(ctx.get(), wrapped.data(), &n, aes.data.data(), aes.data.size()),
             "RSA wrapped key");
    wrapped.resize(n);
    if (wrapped.size() != static_cast<std::size_t>(EVP_PKEY_get_size(pub)))
        fail(5, "unexpected wrapped key size");
    return wrapped;
}

// Mọi lỗi giải mã OAEP đều trả về cùng thông báo, không để lộ lỗi padding.
void unwrapKey(EVP_PKEY* priv, const Bytes& wrapped, SecureKey& aes) {
    PKeyCtx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, priv, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) fail(5, "cannot create RSA context: " + opensslError());
    sslCheck(EVP_PKEY_decrypt_init(ctx.get()), "RSA decrypt init");
    configureOaep(ctx.get());
    std::size_t n = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &n, wrapped.data(), wrapped.size()) <= 0) {
        ERR_clear_error();
        fail(4, "decryption failed");
    }
    Bytes recovered(n);
    if (EVP_PKEY_decrypt(ctx.get(), recovered.data(), &n, wrapped.data(), wrapped.size()) <= 0 ||
        n != AES_KEY_LEN) {
        if (!recovered.empty()) OPENSSL_cleanse(recovered.data(), recovered.size());
        ERR_clear_error();
        fail(4, "decryption failed");
    }
    std::copy_n(recovered.begin(), AES_KEY_LEN, aes.data.begin());
    OPENSSL_cleanse(recovered.data(), recovered.size());
}

void putU16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<unsigned char>(v >> 8));
    b.push_back(static_cast<unsigned char>(v));
}
void putU64(Bytes& b, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8)
        b.push_back(static_cast<unsigned char>(v >> shift));
}
std::uint16_t getU16(const unsigned char* p) {
    return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}
std::uint64_t getU64(const unsigned char* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// Ghi vào <out>.part; chỉ đổi sang tên chính thức khi công việc thành công.
class PendingOutput {
public:
    fs::path finalPath;
    fs::path partPath;
    bool done = false;
    bool force = false;

    PendingOutput(const fs::path& requested, bool allowOverwrite)
        : finalPath(requested), partPath(fs::path(requested.string() + ".part")),
          force(allowOverwrite) {
        std::error_code ec;
        if (fs::exists(finalPath, ec) && !force) fail(2, "output exists (use --force)");
        if (fs::exists(partPath, ec)) fail(2, "temporary .part file already exists");
    }

    ~PendingOutput() {
        if (!done) {
            std::error_code ec;
            fs::remove(partPath, ec);
        }
    }

    void commit() {
        std::error_code ec;
        if (force && fs::exists(finalPath, ec)) {
            fs::remove(finalPath, ec);  // Chỉ xóa kết quả cũ sau khi hoàn tất xác thực.
            if (ec) fail(2, "cannot replace existing output");
        }
        fs::rename(partPath, finalPath, ec);
        if (ec) fail(2, "cannot finalize output: " + ec.message());
        done = true;
    }
};

void rejectSameFile(const fs::path& input, const fs::path& output) {
    std::error_code ec;
    if (fs::exists(output, ec) && fs::equivalent(input, output, ec) && !ec)
        fail(1, "input and output paths must be different");
    if (fs::absolute(input).lexically_normal() == fs::absolute(output).lexically_normal())
        fail(1, "input and output paths must be different");
}

// Header v1: L2PK | version | mode | reserved | klen | wrapped_key | nonce | ct_len.
// Toàn bộ header được xác thực bằng AES-GCM AAD.
std::size_t encryptFile(EVP_PKEY* pub, const fs::path& input,
                        const fs::path& output, bool force) {
    checkRsaKey(pub);
    rejectSameFile(input, output);
    const std::uint64_t n = lengthOf(input);
    if (n > MAX_FILE) fail(3, "input exceeds 1 GiB limit");
    std::ifstream in(input, std::ios::binary);
    if (!in) fail(2, "cannot open input file");
    PendingOutput target(output, force);
    rejectSameFile(input, target.partPath);

    SecureKey aes;
    std::array<unsigned char, NONCE_LEN> nonce{};
    sslCheck(RAND_bytes(aes.data.data(), static_cast<int>(aes.data.size())), "AES key RNG");
    sslCheck(RAND_bytes(nonce.data(), static_cast<int>(nonce.size())), "nonce RNG");
    const Bytes wrapped = wrapKey(pub, aes);

    Bytes header{'L', '2', 'P', 'K', VERSION, MODE_OAEP, 0x00, 0x00};
    if (wrapped.size() > std::numeric_limits<std::uint16_t>::max())
        fail(5, "RSA key is too large for package");
    putU16(header, static_cast<std::uint16_t>(wrapped.size()));
    header.insert(header.end(), wrapped.begin(), wrapped.end());
    header.insert(header.end(), nonce.begin(), nonce.end());
    putU64(header, n);

    std::ofstream out(target.partPath, std::ios::binary | std::ios::trunc);
    if (!out) fail(2, "cannot create output .part");
    writeExact(out, header.data(), header.size());

    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) fail(5, "cannot create AES-GCM context");
    sslCheck(EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(),
                                 aes.data.data(), nonce.data(), nullptr), "GCM encrypt init");
    int produced = 0;
    sslCheck(EVP_EncryptUpdate(ctx.get(), nullptr, &produced, header.data(),
                               static_cast<int>(header.size())), "GCM header AAD");
    std::array<unsigned char, BLOCK> inBuf{};
    std::array<unsigned char, BLOCK + 16> outBuf{};
    std::uint64_t remaining = n;
    while (remaining > 0) {
        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, BLOCK));
        readExact(in, inBuf.data(), chunk);
        sslCheck(EVP_EncryptUpdate(ctx.get(), outBuf.data(), &produced,
                                   inBuf.data(), static_cast<int>(chunk)), "GCM encrypt update");
        writeExact(out, outBuf.data(), static_cast<std::size_t>(produced));
        remaining -= chunk;
    }
    sslCheck(EVP_EncryptFinal_ex(ctx.get(), outBuf.data(), &produced), "GCM encrypt final");
    writeExact(out, outBuf.data(), static_cast<std::size_t>(produced));
    std::array<unsigned char, TAG_LEN> tag{};
    sslCheck(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
                                 static_cast<int>(tag.size()), tag.data()), "GCM get tag");
    writeExact(out, tag.data(), tag.size());
    out.close();
    if (!out) fail(2, "cannot close encrypted file");
    target.commit();
    return header.size();
}

struct PackageInfo {
    Bytes header;
    Bytes wrapped;
    std::array<unsigned char, NONCE_LEN> nonce{};
    std::uint64_t ctLen = 0;
    std::size_t k = 0;
};

// Kiểm tra đầy đủ định dạng trước khi giải mã hoặc cấp phát theo ct_len.
PackageInfo parsePackage(std::ifstream& in, std::uint64_t fileSize,
                         EVP_PKEY* priv, bool strictReserved = true) {
    if (fileSize < 10 + NONCE_LEN + 8 + TAG_LEN) fail(3, "truncated package");
    std::array<unsigned char, 10> first{};
    readExact(in, first.data(), first.size());
    if (std::memcmp(first.data(), "L2PK", 4) != 0) fail(3, "bad package magic");
    if (first[4] != VERSION) fail(3, "unsupported package version");
    if (first[5] != MODE_OAEP) fail(3, "unexpected package mode");
    if (strictReserved && (first[6] != 0 || first[7] != 0))
        fail(3, "reserved bytes must be zero");

    const auto k = static_cast<std::size_t>(EVP_PKEY_get_size(priv));
    const auto klen = static_cast<std::size_t>(getU16(first.data() + 8));
    if (klen != k) fail(3, "klen does not match RSA modulus size");
    const auto headerSize = 30 + klen;
    if (fileSize < static_cast<std::uint64_t>(headerSize + TAG_LEN))
        fail(3, "truncated package");

    PackageInfo info;
    info.k = k;
    info.header.assign(first.begin(), first.end());
    info.header.resize(headerSize);
    readExact(in, info.header.data() + 10, headerSize - 10);
    const auto* p = info.header.data();
    info.ctLen = getU64(p + 22 + klen);
    if (info.ctLen > MAX_FILE) fail(3, "ciphertext length exceeds 1 GiB limit");
    if (fileSize != static_cast<std::uint64_t>(headerSize) + info.ctLen + TAG_LEN)
        fail(3, "package total length mismatch");
    info.wrapped.assign(p + 10, p + 10 + klen);
    std::copy_n(p + 10 + klen, NONCE_LEN, info.nonce.begin());
    return info;
}

std::size_t decryptFile(EVP_PKEY* priv, const fs::path& input,
                        const fs::path& output, bool force, bool strictReserved = true) {
    checkRsaKey(priv);
    rejectSameFile(input, output);
    const auto fileSize = lengthOf(input);
    std::ifstream in(input, std::ios::binary);
    if (!in) fail(2, "cannot open package");
    const PackageInfo info = parsePackage(in, fileSize, priv, strictReserved);
    PendingOutput target(output, force);
    rejectSameFile(input, target.partPath);
    SecureKey aes;
    unwrapKey(priv, info.wrapped, aes);

    CipherCtx ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) fail(5, "cannot create AES-GCM context");
    sslCheck(EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_gcm(),
                                 aes.data.data(), info.nonce.data(), nullptr), "GCM decrypt init");
    int produced = 0;
    sslCheck(EVP_DecryptUpdate(ctx.get(), nullptr, &produced, info.header.data(),
                               static_cast<int>(info.header.size())), "GCM header AAD");
    std::ofstream out(target.partPath, std::ios::binary | std::ios::trunc);
    if (!out) fail(2, "cannot create output .part");
    std::array<unsigned char, BLOCK> inBuf{};
    SecureChunk ptBuf;
    std::uint64_t remaining = info.ctLen;
    while (remaining > 0) {
        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, BLOCK));
        readExact(in, inBuf.data(), chunk);
        sslCheck(EVP_DecryptUpdate(ctx.get(), ptBuf.data.data(), &produced,
                                   inBuf.data(), static_cast<int>(chunk)), "GCM decrypt update");
        writeExact(out, ptBuf.data.data(), static_cast<std::size_t>(produced));
        remaining -= chunk;
    }
    std::array<unsigned char, TAG_LEN> tag{};
    readExact(in, tag.data(), tag.size());
    sslCheck(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                                 static_cast<int>(tag.size()), tag.data()), "GCM set tag");
    if (EVP_DecryptFinal_ex(ctx.get(), ptBuf.data.data(), &produced) != 1) {
        ERR_clear_error();
        out.close();
        fail(4, "decryption failed");
    }
    writeExact(out, ptBuf.data.data(), static_cast<std::size_t>(produced));
    out.close();
    if (!out) fail(2, "cannot close decrypted file");
    target.commit();
    return info.header.size();
}

std::string hexHead(const unsigned char* p, std::size_t n) {
    static const char* table = "0123456789ABCDEF";
    std::string str;
    for (std::size_t i = 0; i < n; ++i) {
        if (i) str += ' ';
        str += table[p[i] >> 4];
        str += table[p[i] & 15];
    }
    return str;
}

void reportPackage(const fs::path& package, std::size_t headerSize) {
    const Bytes small = readSmallFile(package, 8192 + 4096);
    const std::size_t total = small.size();
    if (total < headerSize + TAG_LEN) fail(5, "demo package truncated");
    std::cout << "  magic/version/mode: " << hexHead(small.data(), 8) << "\n";
    std::cout << "  header (first 16): " << hexHead(small.data(), std::min<std::size_t>(16, headerSize)) << "\n";
    std::cout << "  ciphertext (first 16): "
              << hexHead(small.data() + headerSize,
                         std::min<std::size_t>(16, total - headerSize - TAG_LEN)) << "\n";
    std::cout << "  tag: " << hexHead(small.data() + total - TAG_LEN, TAG_LEN) << "\n";
    std::cout << "  wrote " << package.string() << " (" << total << " = " << headerSize
              << " header + " << total - headerSize - TAG_LEN << " ciphertext + 16 tag)\n";
}

// Phần demo giữ đúng ý tưởng PDF: round trip, ngẫu nhiên và thay đổi từng trường.
// Các bài kiểm thử dự án lớn (50 MiB, PEM/DER, D-T11) sẽ kiểm tra riêng qua CLI.
int selfTest(EVP_PKEY* pub, EVP_PKEY* priv, const fs::path* userInput) {
    const fs::path input = userInput ? *userInput : fs::path("demo_input.bin");
    if (!userInput) {
        const std::string message = "Meet at the library at 10:00. Bring the USB key.";
        writeSmallFile(input, Bytes(message.begin(), message.end()));
    }
    const auto bytes = lengthOf(input);
    if (bytes > 8192) fail(1, "in-class demo accepts up to 8192 bytes; use encrypt for larger files");
    const fs::path package("demo.l2pk"), decoded("demo_decoded.bin");
    const fs::path second("demo_second.l2pk"), tampered("demo_tampered.l2pk");
    const fs::path shouldNotExist("demo_failed_plain.bin");

    int passed = 0, total = 0;
    const auto check = [&](const std::string& name, bool condition) {
        ++total;
        if (condition) ++passed;
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << "\n";
    };

    std::cout << "== Task D: RSA-OAEP + AES-256-GCM, " << bytes << "-byte message ==\n";
    const std::size_t headerSize = encryptFile(pub, input, package, true);
    reportPackage(package, headerSize);
    decryptFile(priv, package, decoded, true);
    check("round trip recovers the message", readSmallFile(input, 8192) == readSmallFile(decoded, 8192));
    encryptFile(pub, input, second, true);
    check("sealing twice gives different packages", readSmallFile(package, 8192 + 4096) != readSmallFile(second, 8192 + 4096));

    const Bytes original = readSmallFile(package, 8192 + 4096);
    const auto expectFailure = [&](const char* label, std::size_t offset,
                                   int expectedCode, bool strictReserved = true) {
        Bytes changed = original;
        if (offset >= changed.size()) fail(5, "selftest offset out of range");
        changed[offset] ^= 0x01;
        writeSmallFile(tampered, changed);
        std::error_code ec;
        fs::remove(shouldNotExist, ec);
        bool failedCorrectly = false;
        std::string why;
        try { decryptFile(priv, tampered, shouldNotExist, false, strictReserved); }
        catch (const LabError& e) { why = e.what(); failedCorrectly = e.exitCode == expectedCode; }
        const bool noPlaintext = !fs::exists(shouldNotExist) && !fs::exists(fs::path(shouldNotExist.string() + ".part"));
        std::cout << "  flip " << label << " -> " << why << "\n";
        check(label, failedCorrectly && noPlaintext);
    };
    std::cout << "\n-- tampering (each must fail, no plaintext) --\n";
    if (bytes != 0) expectFailure("first ciphertext byte", headerSize, 4);
    expectFailure("last tag byte", original.size() - 1, 4);
    expectFailure("first nonce byte", 10 + EVP_PKEY_get_size(priv), 4);
    expectFailure("a byte of the wrapped key", 15, 4);
    expectFailure("version byte", 4, 3);
    expectFailure("reserved byte (strict parser)", 7, 3);
    // Chỉ dùng chế độ bỏ qua kiểm tra reserved trong selftest để chứng minh AAD.
    // Lệnh decrypt thông thường LUÔN bật strictReserved.
    expectFailure("reserved byte (lax parser, AAD)", 7, 4, false);
    expectFailure("magic byte", 0, 3);

    Bytes truncated = original;
    truncated.pop_back();
    writeSmallFile(tampered, truncated);
    bool rejectsTruncation = false;
    try { decryptFile(priv, tampered, shouldNotExist, false); }
    catch (const LabError& e) { rejectsTruncation = (e.exitCode == 3); }
    check("truncated package rejected", rejectsTruncation && !fs::exists(shouldNotExist));

    PKey other(EVP_RSA_gen(EVP_PKEY_get_bits(priv)), EVP_PKEY_free);
    if (!other) fail(5, "cannot generate second RSA key: " + opensslError());
    bool rejectsWrongKey = false;
    try { decryptFile(other.get(), package, shouldNotExist, false); }
    catch (const LabError& e) { rejectsWrongKey = e.exitCode == 4; }
    check("wrong private key cannot open", rejectsWrongKey && !fs::exists(shouldNotExist));

    std::error_code ec;
    fs::remove(tampered, ec);
    fs::remove(second, ec);
    std::cout << "\n" << passed << "/" << total << " PASS\n";
    return passed == total ? 0 : 5;
}

void usage() {
    std::cout
        << "Lab 3 Task D - RSA-OAEP-SHA256 + AES-256-GCM\n"
        << "  task_d_hybrid.exe                                  (demo, fresh RSA key)\n"
        << "  task_d_hybrid.exe <public.pem> <private.pem> <file> (demo with Task B keys)\n"
        << "  task_d_hybrid.exe --all                             (in-class selftest)\n"
        << "  task_d_hybrid.exe encrypt --pub <key> --in <file> --out <package> [--force]\n"
        << "  task_d_hybrid.exe decrypt --priv <key> --in <package> --out <file> [--force]\n"
        << "  task_d_hybrid.exe --help\n";
}

struct CliArgs { fs::path key; fs::path input; fs::path output; bool force = false; };
CliArgs parseCli(int argc, char** argv, bool isEncrypt) {
    CliArgs a;
    bool hasKey = false, hasIn = false, hasOut = false;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--force") { if (a.force) fail(1, "duplicate --force"); a.force = true; continue; }
        if (arg == (isEncrypt ? "--pub" : "--priv")) {
            if (hasKey || i + 1 >= argc) fail(1, "invalid key option");
            a.key = argv[++i]; hasKey = true;
        } else if (arg == "--in") {
            if (hasIn || i + 1 >= argc) fail(1, "invalid --in option");
            a.input = argv[++i]; hasIn = true;
        } else if (arg == "--out") {
            if (hasOut || i + 1 >= argc) fail(1, "invalid --out option");
            a.output = argv[++i]; hasOut = true;
        } else fail(1, "unknown or unsupported argument: " + arg);
    }
    if (!hasKey || !hasIn || !hasOut) fail(1, "missing --pub/--priv, --in, or --out");
    return a;
}
}  // namespace

int entry(int argc, char** argv) {
    try {
        if (argc == 1 || (argc == 2 && std::string(argv[1]) == "--all")) {
            PKey key(EVP_RSA_gen(3072), EVP_PKEY_free);
            if (!key) fail(5, "cannot generate demo RSA key: " + opensslError());
            return selfTest(key.get(), key.get(), nullptr);
        }
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "help")) {
            usage(); return 0;
        }
        if (argc == 4 && argv[1][0] != '-') {
            PKey pub = loadKey(argv[1], false);
            PKey priv = loadKey(argv[2], true);
            const fs::path input(argv[3]);
            return selfTest(pub.get(), priv.get(), &input);
        }
        const std::string command = argv[1];
        if (command == "encrypt" || command == "decrypt") {
            const bool encrypt = command == "encrypt";
            const CliArgs args = parseCli(argc, argv, encrypt);
            PKey key = loadKey(args.key, !encrypt);
            const std::size_t headerSize = encrypt ? encryptFile(key.get(), args.input, args.output, args.force)
                                                    : decryptFile(key.get(), args.input, args.output, args.force);
            std::cout << (encrypt ? "ENCRYPT OK" : "DECRYPT OK")
                      << " | header=" << headerSize << " bytes | output=" << args.output.string() << "\n";
            return 0;
        }
        usage();
        return 1;
    } catch (const LabError& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return e.exitCode;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 5;
    }
}

} // namespace task_d
