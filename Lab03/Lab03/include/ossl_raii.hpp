#pragma once
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>
namespace lab {
struct Error : std::runtime_error {
    int code;
    int exitCode;
    Error(int value, const std::string& message) : std::runtime_error(message), code(value), exitCode(value) {}
};
inline std::string drainErrors() {
    std::string result;
    for (unsigned long n; (n=ERR_get_error())!=0;) {
        char text[256]{}; ERR_error_string_n(n,text,sizeof text);
        if (!result.empty()) result += "; ";
        result += text;
    }
    return result;
}
struct BufferWiper {
    std::vector<unsigned char>& data;
    bool enabled=true;
    ~BufferWiper() { if(enabled && !data.empty()) OPENSSL_cleanse(data.data(),data.size()); }
};
// Move-only ownership: secret bytes are wiped on success and exception paths.
struct SecureBytes {
    std::vector<unsigned char> value;
    explicit SecureBytes(std::size_t n=0):value(n) {}
    SecureBytes(const SecureBytes&)=delete;
    SecureBytes& operator=(const SecureBytes&)=delete;
    SecureBytes(SecureBytes&& other) noexcept : value(std::move(other.value)) {}
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this!=&other) { cleanse(); value=std::move(other.value); }
        return *this;
    }
    void cleanse() noexcept { if (!value.empty()) OPENSSL_cleanse(value.data(),value.size()); }
    ~SecureBytes() { cleanse(); }
};
}
