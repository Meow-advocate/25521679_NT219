#pragma once
#include "ossl_raii.hpp"
#include <openssl/evp.h>
#include <filesystem>
#include <memory>
#include <string>
namespace task_b {
using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
Key loadKey(const std::filesystem::path& file,bool privatePart,const std::string& forcedFormat="");
void validatePublic(EVP_PKEY* key);
void validatePrivate(EVP_PKEY* key);
std::string digestKeyId(EVP_PKEY* key);
}
