#include "sp800_38a.hpp"
#include "sp800_38b.hpp"
#include "sp800_38c.hpp"
#include "sp800_38d.hpp"
#include "sp800_38e.hpp"
#include "sp800_38f.hpp"
#include "rfc8452_gcm_siv.hpp"
#include <iostream>
#include <string>
#include <stdexcept>
using common::Bytes;
static Bytes hx(const char*s){return common::parse_hex(s);}
static Bytes as_bytes(const Block& b){return Bytes(b.begin(),b.end());}
static Block as_block(const char*s){return common::block_at(hx(s),0);}
static int tests=0, passed=0;
static void check(const std::string& label,const Bytes& actual,const Bytes& expected){
    ++tests;
    bool ok=actual==expected;
    if(ok)++passed;
    std::cout<<(ok?"PASS ":"FAIL ")<<label<<"\n";
    if(!ok)std::cout<<"  actual   "<<common::hex(actual)<<"\n  expected "<<common::hex(expected)<<"\n";
}
int main(){
 try {
    const Bytes key=hx("2b7e151628aed2a6abf7158809cf4f3c");AES aes(key);
    const Bytes iv=hx("000102030405060708090a0b0c0d0e0f");
    const Bytes P=hx("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    // NIST SP 800-38A, các bảng F.1..F.5
    Bytes cipher=nist::ecb_encrypt(aes,P,false);
    check("ECB",cipher,hx("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"));
    if(nist::ecb_decrypt(aes,cipher,false)!=P)throw std::runtime_error("ECB decrypt failed");
    cipher=nist::cbc_encrypt(aes,P,iv,false);
    check("CBC",cipher,hx("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"));
    if(nist::cbc_decrypt(aes,cipher,iv,false)!=P)throw std::runtime_error("CBC decrypt failed");
    cipher=nist::cfb128_encrypt(aes,P,iv);
    check("CFB128",cipher,hx("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"));
    if(nist::cfb128_decrypt(aes,cipher,iv)!=P)throw std::runtime_error("CFB128 decrypt failed");
    cipher=nist::cfb8_encrypt(aes,P,iv);
    check("CFB8",Bytes(cipher.begin(),cipher.begin()+16),hx("3b79424c9c0dd436bace9e0ed4586a4f"));
    if(nist::cfb8_decrypt(aes,cipher,iv)!=P)throw std::runtime_error("CFB8 decrypt failed");
    cipher=nist::ofb_transform(aes,P,iv);
    check("OFB",cipher,hx("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"));
    if(nist::ofb_transform(aes,cipher,iv)!=P)throw std::runtime_error("OFB decrypt failed");
    Bytes counter=hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    cipher=nist::ctr_transform(aes,P,counter);
    check("CTR",cipher,hx("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"));
    if(nist::ctr_transform(aes,cipher,counter)!=P)throw std::runtime_error("CTR decrypt failed");
    // NIST SP 800-38B - CMAC: examples with empty data and first AES test block.
    check("CMAC empty",as_bytes(nist::cmac(aes,Bytes{})),hx("bb1d6929e95937287fa37d129b756746"));
    check("CMAC 16B",as_bytes(nist::cmac(aes,Bytes(P.begin(),P.begin()+16))),hx("070a16b46b4d4144f79bdd9dd04a287c"));
    // RFC 3610, packet vector 1 (AAD 8B, plaintext 23B, 8-byte tag).
    AES aes_ccm(hx("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"));
    Bytes nonce=hx("00000003020100a0a1a2a3a4a5");
    Bytes aad=hx("0001020304050607"), msg=hx("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    auto ccm=nist::ccm_encrypt(aes_ccm,msg,nonce,aad,8);
    check("CCM RFC3610 ct",ccm.ciphertext,hx("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"));
    check("CCM RFC3610 tag",ccm.tag,hx("17e8d12cfdf926e0"));
    if(nist::ccm_decrypt(aes_ccm,ccm.ciphertext,nonce,aad,ccm.tag)!=msg)throw std::runtime_error("CCM decrypt failed");
    // NIST GCM zero-key cases: zero-message tag, one block ciphertext and tag.
    AES aes_zero(Bytes(16,0));Bytes nonce_gcm(12,0);
    auto g0=nist::gcm_encrypt(aes_zero,{},nonce_gcm,{});
    check("GCM empty",as_bytes(g0.tag),hx("58e2fccefa7e3061367f1d57a4e7455a"));
    auto g1=nist::gcm_encrypt(aes_zero,Bytes(16,0),nonce_gcm,{});
    check("GCM ct",g1.ciphertext,hx("0388dace60b6a392f328c2b971b2fe78"));
    check("GCM tag",as_bytes(g1.tag),hx("ab6e47d42cec13bdf53a67b21257bddf"));
    if(nist::gcm_decrypt(aes_zero,g1.ciphertext,nonce_gcm,{},g1.tag)!=Bytes(16,0))throw std::runtime_error("GCM decrypt failed");
    // RFC 3394 / RFC 5649 - Key Wrap and Key Wrap with Padding.
    AES kw_aes(hx("000102030405060708090a0b0c0d0e0f"));
    Bytes kwp=hx("00112233445566778899aabbccddeeff");
    Bytes wrapped=nist::kw_wrap(kw_aes,kwp);
    check("KW RFC3394",wrapped,hx("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"));
    if(nist::kw_unwrap(kw_aes,wrapped)!=kwp)throw std::runtime_error("KW unwrap failed");
    AES kwp_aes(hx("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
    Bytes kwp_data=hx("c37b7e6492584340bed12207808941155068f738");
    Bytes kwpc=nist::kwp_wrap(kwp_aes,kwp_data);
    check("KWP RFC5649",kwpc,hx("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"));
    if(nist::kwp_unwrap(kwp_aes,kwpc)!=kwp_data)throw std::runtime_error("KWP unwrap failed");
    // XTS IEEE 1619: double key (decimal digits of e and pi as hex), zero tweak.
    Bytes xtskey=hx("2718281828459045235360287471352631415926535897932384626433832795");
    Bytes xts_p=hx("000102030405060708090a0b0c0d0e0f");
    Bytes xts_c=nist::xts_encrypt(xtskey,xts_p,Block{});
    check("XTS IEEE block",xts_c,hx("27a7479befa1d476489f308cd4cfa6e2"));
    if(nist::xts_decrypt(xtskey,xts_c,Block{})!=xts_p)throw std::runtime_error("XTS decrypt failed");
    // RFC8452 appendix C.1: AES-128-GCM-SIV with empty and 8-byte plaintext.
    Bytes siv_key=hx("01000000000000000000000000000000"),siv_nonce=hx("030000000000000000000000");
    auto s0=nist::gcm_siv_encrypt(siv_key,{},siv_nonce,{});
    check("GCM-SIV128 empty",as_bytes(s0.tag),hx("dc20e2d83f25705bb49e439eca56de25"));
    auto s1=nist::gcm_siv_encrypt(siv_key,hx("0100000000000000"),siv_nonce,{});
    Bytes combined=s1.ciphertext;common::append(combined,s1.tag);
    check("GCM-SIV128 8B ct+tag",combined,hx("b5d839330ac7b786578782fff6013b815b287c22493a364c"));
    if(nist::gcm_siv_decrypt(siv_key,s1.ciphertext,siv_nonce,{},s1.tag)!=hx("0100000000000000"))throw std::runtime_error("SIV decrypt failed");
    std::cout << "ALL " << passed << "/" << tests << " VECTORS "<<(tests==passed?"PASS":"FAIL")<<"\n";
    return tests==passed?0:1;
 } catch(const std::exception& err) {std::cerr<<"EXCEPTION: "<<err.what()<<"\n";return 2;}
}
