// Public-interface test; no reference implementation is included in this executable.
#include "bn_math.hpp"
#include "rsa_encoding.hpp"
#include "rsa_kem.hpp"
#include <openssl/rsa.h>
#include <iostream>
#include <memory>
#include <stdexcept>
static void expect(bool value) { if(!value) throw std::runtime_error("public API check failed"); }
int main() {
 try {
  auto a=std::unique_ptr<BIGNUM,decltype(&BN_free)>(BN_new(),BN_free);
  auto b=std::unique_ptr<BIGNUM,decltype(&BN_free)>(BN_new(),BN_free);
  auto m=std::unique_ptr<BIGNUM,decltype(&BN_free)>(BN_new(),BN_free);
  expect(a && b && m); expect(BN_set_word(a.get(),7)==1 && BN_set_word(b.get(),13)==1 && BN_set_word(m.get(),33)==1);
  expect(BN_is_word(task_a::modOperation(a.get(),b.get(),m.get(),"mod-exp").get(),13)==1);
  const std::vector<unsigned char> bytes{0,255,0};auto number=task_c::os2ip(bytes);expect(task_c::i2osp(number.get(),3)==bytes);
  auto key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>(EVP_RSA_gen(2048),EVP_PKEY_free);expect(bool(key));
  auto enc=task_e::encapsulate(key.get());auto recovered=task_e::decapsulate(key.get(),enc.kem_ct);
  expect(enc.shared_secret.value.size()==recovered.value.size());expect(CRYPTO_memcmp(enc.shared_secret.value.data(),recovered.value.data(),recovered.value.size())==0);
  const std::vector<unsigned char> id(32,0);auto aes=task_e::deriveAesKey(recovered,id,enc.kem_ct);expect(aes.value.size()==32);
  std::cout<<"PASS public math, encoding and KEM APIs\n";return 0;
 } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
