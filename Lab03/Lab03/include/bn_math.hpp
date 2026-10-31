#pragma once
#include <openssl/bn.h>
#include <memory>
#include <string>
namespace task_a {
using BigNum=std::unique_ptr<BIGNUM,decltype(&BN_free)>;
BigNum modOperation(const BIGNUM* a,const BIGNUM* b,const BIGNUM* m,const std::string& operation);
BigNum greatestCommonDivisor(const BIGNUM* a,const BIGNUM* b);
BigNum modularInverse(const BIGNUM* a,const BIGNUM* m);
BigNum squareAndMultiply(const BIGNUM* a,const BIGNUM* exponent,const BIGNUM* m);
BigNum extendedEuclidInverse(const BIGNUM* a,const BIGNUM* m,BIGNUM* gcd);
}
