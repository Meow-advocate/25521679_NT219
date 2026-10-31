#pragma once
#include <openssl/bn.h>
#include <memory>
#include <vector>
namespace task_c {
using Big=std::unique_ptr<BIGNUM,decltype(&BN_clear_free)>;
Big os2ip(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> i2osp(const BIGNUM* value,std::size_t width);
}
