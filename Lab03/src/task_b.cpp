#include "rsa_params.hpp"
#include <string_view>
#include "key_io.hpp"
#include "task_cli.hpp"
#include "ossl_raii.hpp"
// Lab 03 - Task B: Tham số RSA, tạo khóa, PEM/DER, kiểm tra và chuyển đổi khóa.
// Mã nguồn được viết độc lập theo các yêu cầu B-F1 đến B-F7 của tài liệu lab.
// Các khóa riêng không mã hóa chỉ phục vụ thực hành; không dùng cho hệ thống thật.

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace task_b {

using namespace std;
namespace fs = std::filesystem;

using Bn = unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BnContext = unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using Key = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContext = unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Bio = unique_ptr<BIO, decltype(&BIO_free)>;
using Pkcs8 = unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>;
using Bytes = vector<unsigned char>;

using LabError = lab::Error;

void ensure(bool success, const string& message, int code = 1) {
    if (!success) { const std::string queue=lab::drainErrors(); throw LabError(code, message + (queue.empty() || code==4 ? "" : ": " + queue)); }
}

void ensureCrypto(bool success,const string& message,int code=5) { ensure(success,message,code); }

Bn newBn() {
    Bn x(BN_new(), BN_clear_free);
    ensureCrypto(bool(x), "Khong tao duoc BIGNUM");
    return x;
}

BnContext newCtx() {
    BnContext ctx(BN_CTX_new(), BN_CTX_free);
    ensureCrypto(bool(ctx), "Khong tao duoc BN_CTX");
    return ctx;
}

// Chuyển BIGNUM sang chuỗi và giải phóng vùng nhớ do OpenSSL cấp.
string bnToText(const BIGNUM* value, bool hex = false) {
    char* raw = hex ? BN_bn2hex(value) : BN_bn2dec(value);
    ensureCrypto(raw != nullptr, "Khong chuyen duoc BIGNUM sang chuoi");
    string text(raw);
    OPENSSL_free(raw);
    return text;
}

int parseInt(const string& value, int minimum, int maximum, const string& name) {
    ensure(!value.empty() && all_of(value.begin(), value.end(), [](unsigned char c) {
        return c >= '0' && c <= '9';
    }), "Gia tri " + name + " khong hop le");
    long long n = 0;
    for (char c : value) {
        n = n * 10 + (c - '0');
        ensure(n <= maximum, "Gia tri " + name + " vuot gioi han");
    }
    ensure(n >= minimum, "Gia tri " + name + " qua nho");
    return static_cast<int>(n);
}

void requireRsa(EVP_PKEY* key, int minBits = 2048) {
    ensure(key && EVP_PKEY_is_a(key, "RSA") == 1,
           "Chi chap nhan khoa RSA", 3);
    ensure(EVP_PKEY_get_bits(key) >= minBits,
           "Khoa RSA khong du do dai toi thieu " + to_string(minBits) + " bit", 3);
}

Key generateKey(int bits) {
    ensure(bits == 2048 || bits == 3072 || bits == 4096,
           "Chi chap nhan 2048, 3072 hoac 4096 bit");
    KeyContext context(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    ensureCrypto(bool(context), "Khong tao duoc context sinh khoa RSA");
    ensureCrypto(EVP_PKEY_keygen_init(context.get()) > 0, "Khong khoi tao duoc RSA keygen");
    ensureCrypto(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) > 0,
           "Khong dat duoc kich thuoc khoa RSA");
    EVP_PKEY* raw = nullptr;
    int ok = EVP_PKEY_generate(context.get(), &raw);
    Key key(raw, EVP_PKEY_free);
    ensureCrypto(ok > 0 && bool(key), "Sinh khoa RSA that bai");
    requireRsa(key.get());
    return key;
}

// Đọc nhị phân vào bộ nhớ: giới hạn kích thước nhằm tránh cấp phát không kiểm soát.
Bytes readBytes(const fs::path& filename) {
    ifstream stream(filename, ios::binary | ios::ate);
    ensure(bool(stream), "Khong mo duoc file: " + filename.string(), 2);
    streampos size = stream.tellg();
    ensure(size > 0 && size <= streampos(1024 * 1024), "File rong hoac qua lon", 3);
    Bytes data(static_cast<size_t>(size));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<streamsize>(data.size()));
    ensure(bool(stream), "Khong doc het file: " + filename.string(), 2);
    return data;
}

void writeBytes(const fs::path& filename, const Bytes& data, bool overwrite,
                bool privatePart = false) {
    ensure(overwrite || !fs::exists(filename), "File da ton tai: " + filename.string(), 2);
#ifndef _WIN32
    // Trên POSIX, khóa riêng được tạo với quyền 0600 ngay từ lúc mở file.
    int flags = O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL);
    int fd = ::open(filename.c_str(), flags, privatePart ? 0600 : 0644);
    ensure(fd >= 0, "Khong tao duoc file: " + filename.string(), 2);
    if (privatePart && ::fchmod(fd, 0600) != 0) {
        ::close(fd);
        throw LabError(2, "Khong cai duoc quyen 0600 cho file khoa rieng");
    }
    size_t written = 0;
    while (written < data.size()) {
        ssize_t count = ::write(fd, data.data() + written, data.size() - written);
        if (count <= 0) { ::close(fd); throw LabError(2, "Loi ghi file: " + filename.string()); }
        written += static_cast<size_t>(count);
    }
    ensure(::close(fd) == 0, "Khong dong duoc file: " + filename.string(), 2);
#else
    // Windows: quyền do NTFS ACL quyết định; không có chmod 0600 tương đương trực tiếp.
    ofstream stream(filename, ios::binary | ios::trunc);
    ensure(bool(stream), "Khong tao duoc file: " + filename.string(), 2);
    stream.write(reinterpret_cast<const char*>(data.data()), static_cast<streamsize>(data.size()));
    stream.flush();
    ensure(bool(stream), "Khong ghi duoc file: " + filename.string(), 2);
    (void)privatePart;
#endif
}

// Mã hóa SPKI DER hoặc PKCS#8 DER, tuyệt đối không dùng i2d_PrivateKey cho RSA.
Bytes encodeDer(EVP_PKEY* key, bool privatePart) {
    if (!privatePart) {
        int length = i2d_PUBKEY(key, nullptr);
        ensureCrypto(length > 0, "Khong ma hoa duoc SPKI DER");
        Bytes result(static_cast<size_t>(length));
        unsigned char* target = result.data();
        ensureCrypto(i2d_PUBKEY(key, &target) == length, "Loi ghi SPKI DER");
        return result;
    }
    Pkcs8 structure(EVP_PKEY2PKCS8(key), PKCS8_PRIV_KEY_INFO_free);
    ensureCrypto(bool(structure), "Khong tao duoc PKCS#8");
    int length = i2d_PKCS8_PRIV_KEY_INFO(structure.get(), nullptr);
    ensureCrypto(length > 0, "Khong ma hoa duoc PKCS#8 DER");
    Bytes result(static_cast<size_t>(length));
    unsigned char* target = result.data();
    ensureCrypto(i2d_PKCS8_PRIV_KEY_INFO(structure.get(), &target) == length,
           "Loi ghi PKCS#8 DER");
    return result;
}

Bytes encodePem(EVP_PKEY* key, bool privatePart) {
    Bio memory(BIO_new(BIO_s_mem()), BIO_free);
    ensureCrypto(bool(memory), "Khong tao duoc BIO trong bo nho");
    int ok = privatePart
        ? PEM_write_bio_PKCS8PrivateKey(memory.get(), key, nullptr, nullptr, 0, nullptr, nullptr)
        : PEM_write_bio_PUBKEY(memory.get(), key);
    ensureCrypto(ok == 1, "Khong ma hoa duoc khoa PEM");
    char* ptr = nullptr;
    long length = BIO_get_mem_data(memory.get(), &ptr);
    ensureCrypto(length > 0 && ptr != nullptr, "Khong doc duoc noi dung PEM");
    return Bytes(reinterpret_cast<unsigned char*>(ptr),
                 reinterpret_cast<unsigned char*>(ptr) + length);
}

bool startsPem(const Bytes& bytes) {
    const string prefix = "-----BEGIN ";
    return bytes.size() >= prefix.size() && equal(prefix.begin(), prefix.end(), bytes.begin());
}

// Chỉ chấp nhận đúng nhãn SPKI/PKCS#8; không nhận khóa PKCS#1 trá hình.
void validatePemEnvelope(const Bytes& bytes, bool privatePart) {
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    string start = privatePart ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN PUBLIC KEY-----";
    string end = privatePart ? "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
    ensure(text.rfind(start, 0) == 0, "Nhãn PEM khong dung SPKI/PKCS#8", 3);
    size_t headerEnd = start.size();
    ensure(headerEnd < text.size() && (text[headerEnd] == '\r' || text[headerEnd] == '\n'),
           "Dinh dang dau PEM khong hop le", 3);
    size_t endPos = text.find(end, headerEnd);
    ensure(endPos != string::npos && endPos > headerEnd && text[endPos - 1] == '\n',
           "Khong tim thay dong ket thuc PEM", 3);
    size_t after = endPos + end.size();
    ensure(after == text.size() || text[after] == '\n' || text[after] == '\r',
           "Du lieu du sau nhan PEM", 3);
    for (size_t i = after; i < text.size(); ++i) {
        ensure(text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n',
               "Co du lieu sau khoa PEM", 3);
    }
}

// Trả về khóa đúng loại; DER phải được tiêu thụ hết và tái mã hóa y nguyên.
Key loadKey(const fs::path& filename, bool privatePart, const string& forcedFormat) {
    Bytes data = readBytes(filename);
    struct Wipe { Bytes& b; bool yes; ~Wipe(){ if(yes && !b.empty()) OPENSSL_cleanse(b.data(),b.size()); } } wipe{data,privatePart};
    bool pem = forcedFormat.empty() ? startsPem(data) : forcedFormat == "PEM";
    ensure(forcedFormat.empty() || forcedFormat == "PEM" || forcedFormat == "DER",
           "--inform phai la PEM hoac DER");
    EVP_PKEY* raw = nullptr;
    if (pem) {
        validatePemEnvelope(data, privatePart);
        Bio memory(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIO_free);
        ensureCrypto(bool(memory), "Khong tao duoc BIO");
        raw = privatePart
            ? PEM_read_bio_PrivateKey(memory.get(), nullptr, nullptr, nullptr)
            : PEM_read_bio_PUBKEY(memory.get(), nullptr, nullptr, nullptr);
        ensure(raw != nullptr, "Khong giai ma duoc PEM", 3);
    } else {
        const unsigned char* cursor = data.data();
        if (privatePart) {
            Pkcs8 structure(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor,
                                                       static_cast<long>(data.size())),
                             PKCS8_PRIV_KEY_INFO_free);
            ensure(bool(structure), "DER phai la khoa rieng PKCS#8", 3);
            ensure(cursor == data.data() + data.size(), "DER co byte du", 3);
            raw = EVP_PKCS82PKEY(structure.get());
        } else {
            raw = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(data.size()));
            ensure(raw != nullptr, "DER phai la khoa cong khai SPKI", 3);
            if (cursor != data.data() + data.size()) {
                EVP_PKEY_free(raw);
                throw LabError(3, "DER co byte du");
            }
        }
        ensure(raw != nullptr, "Khong giai ma duoc khoa DER", 3);
    }
    Key key(raw, EVP_PKEY_free);
    requireRsa(key.get());
    if (!pem) {
        Bytes canonical = encodeDer(key.get(), privatePart);
        bool match = canonical == data;
        if (privatePart) OPENSSL_cleanse(canonical.data(), canonical.size());
        ensure(match, "DER khong dung dang ma hoa chuan", 3);
    }
    if (privatePart) OPENSSL_cleanse(data.data(), data.size());
    return key;
}

string digestKeyId(EVP_PKEY* key) {
    Bytes der = encodeDer(key, false);
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;
    ensureCrypto(EVP_Digest(der.data(), der.size(), digest, &digestLength, EVP_sha256(), nullptr) == 1
           && digestLength == 32, "Khong bam duoc SHA-256 key ID");
    const char* hex = "0123456789abcdef";
    string result;
    for (unsigned int i = 0; i < digestLength; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 15];
    }
    return result;
}

void validatePublic(EVP_PKEY* key) {
    KeyContext context(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), EVP_PKEY_CTX_free);
    ensure(bool(context), "Khong tao duoc context kiem tra public key", 3);
    ensure(EVP_PKEY_public_check(context.get()) == 1, "Khoa cong khai khong hop le", 3);
}

void validatePrivate(EVP_PKEY* key) {
    KeyContext context(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), EVP_PKEY_CTX_free);
    ensure(bool(context), "Khong tao duoc context kiem tra private key", 3);
    ensure(EVP_PKEY_private_check(context.get()) == 1, "Khoa rieng khong hop le", 3);
    ensure(EVP_PKEY_pairwise_check(context.get()) == 1, "RSA pairwise check that bai", 3);
}

void checkMatch(const fs::path& privateFile, const fs::path& publicFile) {
    Key privateKey = loadKey(privateFile, true);
    Key publicKey = loadKey(publicFile, false);
    validatePrivate(privateKey.get());
    validatePublic(publicKey.get());
    if (EVP_PKEY_eq(privateKey.get(), publicKey.get()) != 1) {
        cout << "MISMATCH\n";
        throw LabError(4, "Khoa cong khai va khoa rieng khong thuoc cung cap");
    }
    cout << "MATCH\n";
}

void keyInfo(const fs::path& publicFile, bool showPem = false) {
    Key key = loadKey(publicFile, false);
    validatePublic(key.get());
    BIGNUM* nRaw = nullptr;
    BIGNUM* eRaw = nullptr;
    int statusN = EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_RSA_N, &nRaw);
    int statusE = EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_RSA_E, &eRaw);
    Bn n(nRaw, BN_clear_free), e(eRaw, BN_clear_free);
    ensureCrypto(statusN == 1 && statusE == 1 && bool(n) && bool(e), "Khong lay duoc n, e");
    cout << "Algorithm: RSA\nBits: " << EVP_PKEY_get_bits(key.get()) << '\n';
    cout << "e: " << bnToText(e.get()) << "\n";
    cout << "n (hex): " << bnToText(n.get(), true) << "\n";
    cout << "Key ID (SHA-256 / SPKI DER): " << digestKeyId(key.get()) << '\n';
    if (showPem) {
        Bytes pem = encodePem(key.get(), false);
        cout << "Public key PEM:\n" << string(pem.begin(), pem.end());
    }
    cout << "Private-key contents are intentionally not displayed.\n";
}

void keygen(int bits, const fs::path& directory, bool force = false) {
    ensure(!fs::exists(directory) || fs::is_directory(directory), "Out-dir khong phai thu muc", 2);
    fs::create_directories(directory);
    const vector<string> files = {"private.pem", "private.der", "public.pem", "public.der"};
    for (const string& filename : files) {
        ensure(force || !fs::exists(directory / filename),
               "Files already exist. Move or rename them before generating a new key.", 2);
    }
    Key key = generateKey(bits);
    validatePrivate(key.get());
    Bytes privatePem = encodePem(key.get(), true);
    lab::BufferWiper wipePem{privatePem};
    Bytes privateDer = encodeDer(key.get(), true);
    lab::BufferWiper wipeDer{privateDer};
    Bytes publicPem = encodePem(key.get(), false);
    Bytes publicDer = encodeDer(key.get(), false);
    writeBytes(directory / "private.pem", privatePem, force, true);
    writeBytes(directory / "private.der", privateDer, force, true);
    writeBytes(directory / "public.pem", publicPem, force);
    writeBytes(directory / "public.der", publicDer, force);
    OPENSSL_cleanse(privatePem.data(), privatePem.size());
    OPENSSL_cleanse(privateDer.data(), privateDer.size());
    cout << "[PASS] Generated RSA-" << EVP_PKEY_get_bits(key.get()) << " key pair\n";
    cout << "[PASS] Saved private.pem, private.der, public.pem, public.der\n";
    cout << "WARNING: Unencrypted private key - lab use only. Protect file access.\n";
    cout << "Windows: review NTFS ACL; POSIX chmod 0600 does not apply directly.\n";
}

void keyConvert(bool privatePart, const fs::path& source, const fs::path& dest,
                const string& outform, const string& inform = "") {
    ensure(outform == "PEM" || outform == "DER", "--outform phai la PEM hoac DER");
    ensure(fs::absolute(source).lexically_normal() != fs::absolute(dest).lexically_normal(),
           "Khong cho ghi de len file dau vao");
    Key key = loadKey(source, privatePart, inform);
    Bytes output = outform == "PEM" ? encodePem(key.get(), privatePart)
                                     : encodeDer(key.get(), privatePart);
    lab::BufferWiper wipeOutput{output,privatePart};
    writeBytes(dest, output, false, privatePart);
    if (privatePart) OPENSSL_cleanse(output.data(), output.size());
    cout << "[PASS] Converted to " << outform << ": " << dest.string() << '\n';
}

// Tạo tham số từ đầu cho khóa minh họa (khác với sinh khóa EVP dùng thực tế).
void educationalRsa(int bits, bool showPrivate) {
    ensure(bits >= 128 && bits <= 1024 && bits % 2 == 0,
           "Educational --bits phai chan va trong [128,1024]");
    cout << "EDUCATIONAL KEY - NOT FOR USE\n";
    auto ctx = newCtx();
    auto p = newBn(), q = newBn(), pm1 = newBn(), qm1 = newBn();
    auto n = newBn(), phi = newBn(), lambda = newBn(), gcd = newBn();
    auto e = newBn(), tmp = newBn(), dP = newBn(), dQ = newBn();
    ensureCrypto(BN_set_word(e.get(), 65537) == 1, "Khong thiet lap duoc e");

    // Chỉ nhận số nguyên tố thỏa gcd(e,p-1)=1 và gcd(e,q-1)=1.
    auto drawPrime = [&](BIGNUM* prime, BIGNUM* minusOne) {
        do {
            ensureCrypto(BN_generate_prime_ex2(prime, bits / 2, 0, nullptr, nullptr,
                                         nullptr, ctx.get()) == 1, "Sinh so nguyen to loi");
            ensureCrypto(BN_copy(minusOne, prime) != nullptr && BN_sub_word(minusOne, 1) == 1,
                   "Tinh prime-1 loi");
            ensureCrypto(BN_gcd(gcd.get(), e.get(), minusOne, ctx.get()) == 1, "Tinh gcd loi");
        } while (!BN_is_one(gcd.get()));
    };
    drawPrime(p.get(), pm1.get());
    do { drawPrime(q.get(), qm1.get()); } while (BN_cmp(p.get(), q.get()) == 0);
    ensureCrypto(BN_mul(n.get(), p.get(), q.get(), ctx.get()) == 1, "Tinh n loi");
    ensureCrypto(BN_mul(phi.get(), pm1.get(), qm1.get(), ctx.get()) == 1, "Tinh phi loi");
    ensureCrypto(BN_gcd(gcd.get(), pm1.get(), qm1.get(), ctx.get()) == 1, "Tinh gcd(p-1,q-1) loi");
    ensureCrypto(BN_div(lambda.get(), nullptr, phi.get(), gcd.get(), ctx.get()) == 1,
           "Tinh lambda loi");
    Bn dPhi(BN_mod_inverse(nullptr, e.get(), phi.get(), ctx.get()), BN_clear_free);
    Bn dLam(BN_mod_inverse(nullptr, e.get(), lambda.get(), ctx.get()), BN_clear_free);
    ensureCrypto(bool(dPhi) && bool(dLam), "Khong tim duoc so mu d");
    ensureCrypto(BN_nnmod(dP.get(), dLam.get(), pm1.get(), ctx.get()) == 1 &&
           BN_nnmod(dQ.get(), dLam.get(), qm1.get(), ctx.get()) == 1,
           "Tinh CRT exponent loi");
    Bn qInv(BN_mod_inverse(nullptr, q.get(), p.get(), ctx.get()), BN_clear_free);
    ensureCrypto(bool(qInv), "Tinh qInv loi");

    auto verifyInverse = [&](BIGNUM* d, BIGNUM* modulus) {
        ensureCrypto(BN_mod_mul(tmp.get(), e.get(), d, modulus, ctx.get()) == 1,
               "Kiem tra ed mod loi");
        return BN_is_one(tmp.get());
    };
    bool checkPhi = verifyInverse(dPhi.get(), phi.get());
    bool checkLambda = verifyInverse(dLam.get(), lambda.get());
    bool roundtrips = true, crtPass = true;
    auto m = newBn(), cipher = newBn(), directPhi = newBn(), directLam = newBn();
    auto m1 = newBn(), m2 = newBn(), h = newBn(), crt = newBn(), hq = newBn();
    for (int i = 0; i < 20; ++i) {
        ensureCrypto(BN_rand_range(m.get(), n.get()) == 1, "Sinh thong diep ngau nhien loi");
        ensureCrypto(BN_mod_exp(cipher.get(), m.get(), e.get(), n.get(), ctx.get()) == 1,
               "Ma hoa RSA minh hoa loi");
        ensureCrypto(BN_mod_exp(directPhi.get(), cipher.get(), dPhi.get(), n.get(), ctx.get()) == 1 &&
               BN_mod_exp(directLam.get(), cipher.get(), dLam.get(), n.get(), ctx.get()) == 1,
               "Giai ma RSA minh hoa loi");
        roundtrips &= BN_cmp(directPhi.get(), m.get()) == 0 && BN_cmp(directLam.get(), m.get()) == 0;
        ensureCrypto(BN_mod_exp(m1.get(), cipher.get(), dP.get(), p.get(), ctx.get()) == 1 &&
               BN_mod_exp(m2.get(), cipher.get(), dQ.get(), q.get(), ctx.get()) == 1,
               "Tinh CRT m1,m2 loi");
        ensureCrypto(BN_mod_sub(h.get(), m1.get(), m2.get(), p.get(), ctx.get()) == 1 &&
               BN_mod_mul(h.get(), h.get(), qInv.get(), p.get(), ctx.get()) == 1 &&
               BN_mul(hq.get(), h.get(), q.get(), ctx.get()) == 1 &&
               BN_add(crt.get(), m2.get(), hq.get()) == 1,
               "Tinh CRT m loi");
        crtPass &= BN_cmp(crt.get(), directLam.get()) == 0;
    }
    cout << "n bits: " << BN_num_bits(n.get()) << "\n";
    cout << "n (hex): " << bnToText(n.get(), true) << "\n";
    cout << "e (hex): " << bnToText(e.get(), true) << "\n";
    if (showPrivate) {
        cout << "PRIVATE TOY PARAMETERS - NEVER USE FOR REAL KEYS\n";
        for (auto entry : vector<pair<string, const BIGNUM*>>{
                {"p", p.get()}, {"q", q.get()}, {"phi", phi.get()},
                {"lambda", lambda.get()}, {"d_phi", dPhi.get()},
                {"d_lambda", dLam.get()}, {"dP", dP.get()},
                {"dQ", dQ.get()}, {"qInv", qInv.get()}}) {
            cout << entry.first << ": " << bnToText(entry.second, true) << '\n';
        }
    }
    auto printCheck = [](const string& title, bool pass) {
        cout << (pass ? "[PASS] " : "[FAIL] ") << title << '\n';
    };
    printCheck("e*d_phi == 1 (mod phi)", checkPhi);
    printCheck("e*d_lambda == 1 (mod lambda)", checkLambda);
    printCheck("20 RSA round-trips with both private exponents", roundtrips);
    printCheck("20 CRT decryptions match direct decryptions", crtPass);
    ensureCrypto(checkPhi && checkLambda && roundtrips && crtPass,
           "Kiem thu RSA tham so that bai");
}

string optionValue(const vector<string>& args, const string& name,
                   const string& fallback = "") {
    auto it = find(args.begin(), args.end(), name);
    if (it == args.end()) return fallback;
    ensure(it + 1 != args.end(), "Thieu gia tri cho " + name);
    return *(it + 1);
}

bool hasFlag(const vector<string>& args, const string& flag) {
    return find(args.begin(), args.end(), flag) != args.end();
}

string requiredOption(const vector<string>& args, const string& name) {
    string value = optionValue(args, name);
    ensure(!value.empty(), "Thieu tham so " + name);
    return value;
}

void menu() {
    cout << "OpenSSL header: " << OPENSSL_VERSION_TEXT << '\n';
    cout << "OpenSSL library: " << OpenSSL_version(OPENSSL_VERSION) << '\n';
    while (true) {
        cout << "\n===== RSA KEY LAB - TASK B =====\n"
             << "1. Generate and save RSA-3072 (PEM/DER)\n"
             << "2. Load 4 key files and check MATCH\n"
             << "3. Display PUBLIC key (n, e, PEM, key ID)\n"
             << "4. Educational RSA parameters (512-bit toy)\n"
             << "0. Exit\nChoice: ";
        string choice;
        if (!getline(cin, choice) || choice == "0") return;
        try {
            if (choice == "1") keygen(3072, ".");
            else if (choice == "2") {
                const vector<string> privs = {"private.pem", "private.der"};
                const vector<string> pubs = {"public.pem", "public.der"};
                for (const auto& priv : privs) for (const auto& pub : pubs) {
                    cout << priv << " vs " << pub << ": ";
                    checkMatch(priv, pub);
                }
                cout << "[PASS] All 4 key combinations MATCH\n";
            } else if (choice == "3") keyInfo("public.pem", true);
            else if (choice == "4") educationalRsa(512);
            else cout << "Invalid menu choice.\n";
        } catch (const exception& e) {
            cerr << "[ERROR] " << e.what() << '\n';
        }
    }
}

void usage() {
    cerr << "Usage:\n"
         << "  task_b_rsa_keys.exe rsa-params --bits 512 [--show-private]\n"
         << "  task_b_rsa_keys.exe keygen --bits 3072 --out-dir keys [--force]\n"
         << "  task_b_rsa_keys.exe key-check --priv private.pem --pub public.pem\n"
         << "  task_b_rsa_keys.exe key-info --pub public.pem\n"
         << "  task_b_rsa_keys.exe key-convert --type public|private --in FILE --out FILE --outform PEM|DER [--inform PEM|DER]\n";
}

int entry(int argc, char** argv) {
    try {
        if (argc == 1) { menu(); return 0; }
        vector<string> args(argv + 2, argv + argc);
        string command = argv[1];
        vector<string> allowed;
        if(command=="rsa-params") allowed={"--bits","--show-private"};
        else if(command=="keygen") allowed={"--bits","--out-dir","--force"};
        else if(command=="key-check") allowed={"--priv","--pub"};
        else if(command=="key-info") allowed={"--pub"};
        else if(command=="key-convert") allowed={"--type","--in","--out","--outform","--inform"};
        vector<string> seen;
        for(size_t i=0;i<args.size();++i) {
            const auto flag=args[i];
            ensure(find(allowed.begin(),allowed.end(),flag)!=allowed.end(),"Tham so khong duoc ho tro: "+flag);
            ensure(find(seen.begin(),seen.end(),flag)==seen.end(),"Tham so lap lai: "+flag);
            seen.push_back(flag);
            if(flag!="--force" && flag!="--show-private") {
                ensure(i+1<args.size() && args[i+1].rfind("--",0)!=0,"Thieu gia tri cho "+flag); ++i;
            }
        }
        if (command == "rsa-params") {
            int bits = parseInt(optionValue(args, "--bits", "512"), 128, 1024, "--bits");
            educationalRsa(bits, hasFlag(args, "--show-private"));
        } else if (command == "keygen") {
            int bits = parseInt(optionValue(args, "--bits", "3072"), 2048, 4096, "--bits");
            keygen(bits, requiredOption(args, "--out-dir"), hasFlag(args, "--force"));
        } else if (command == "key-check") {
            checkMatch(requiredOption(args, "--priv"), requiredOption(args, "--pub"));
        } else if (command == "key-info") {
            keyInfo(requiredOption(args, "--pub"));
        } else if (command == "key-convert") {
            string type = requiredOption(args, "--type");
            ensure(type == "public" || type == "private", "--type phai la public hoac private");
            keyConvert(type == "private", requiredOption(args, "--in"),
                       requiredOption(args, "--out"), requiredOption(args, "--outform"),
                       optionValue(args, "--inform"));
        } else {
            usage();
            return 1;
        }
        return 0;
    } catch (const LabError& ex) {
        cerr << "Error: " << ex.what() << '\n';
        return ex.exitCode;
    } catch (const fs::filesystem_error& ex) {
        cerr << "Error: " << ex.what() << '\n';
        return 2;
    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << '\n';
        return 5;
    }
}

} // namespace task_b
