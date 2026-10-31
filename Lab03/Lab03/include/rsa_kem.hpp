#pragma once
#include "ossl_raii.hpp"
#include <openssl/evp.h>
#include <vector>
namespace task_e {
using SecureBytes=lab::SecureBytes;
using Bytes=std::vector<unsigned char>;
struct Encapsulation { Bytes kem_ct; SecureBytes shared_secret; };
Encapsulation encapsulate(EVP_PKEY* recipientPublicKey);
SecureBytes decapsulate(EVP_PKEY* recipientPrivateKey,const Bytes& kem_ct);
SecureBytes deriveAesKey(const SecureBytes& Z,const Bytes& keyId,const Bytes& kem_ct);
namespace edu {
Encapsulation rsasveEncapsulate(EVP_PKEY* recipientPublicKey);
SecureBytes rsasveDecapsulate(EVP_PKEY* recipientPrivateKey,const Bytes& kem_ct);
}
}
