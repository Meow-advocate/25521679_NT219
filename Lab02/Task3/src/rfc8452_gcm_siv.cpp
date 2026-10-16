#include "rfc8452_gcm_siv.hpp"
#include <algorithm>
namespace nist {
using Bytes=common::Bytes;
/*
 * RFC 8452 - AES-GCM-SIV-128 / 256.
 * 1. Sinh hai khóa phụ từ khóa gốc và nonce.
 * 2. POLYVAL xác thực plaintext, AAD -> tổng S.
 * 3. Tag = AES_Kenc(S XOR nonce với bit cao cuối được xóa).
 * 4. Dùng tag làm counter khởi đầu để mã hóa CTR little-endian.
 * Giải mã chỉ trả plaintext khi tag tạo lại khớp với tag đầu vào.
 */
static Block reverse_bytes(Block a) {
    std::reverse(a.begin(),a.end());return a;
}
static Block ghash_multiply(const Block& x,const Block& y) {
    Block z{},v=y;
    for(int bit=0;bit<128;++bit) {
        if((x[bit/8] >> (7-(bit%8))) & 1)
            for(int j=0;j<16;++j)z[j]^=v[j];
        bool carry=(v[15]&1)!=0;
        for(int j=15;j>=0;--j) v[j]=static_cast<Byte>((v[j]>>1)|((j? v[j-1]&1 : 0)<<7));
        if(carry)v[0]^=0xE1;
    }
    return z;
}
static Block ghash_times_x(Block v) {
    bool carry=(v[15]&1)!=0;
    for(int j=15;j>=0;--j)v[j]=static_cast<Byte>((v[j]>>1)|((j? v[j-1]&1 : 0)<<7));
    if(carry)v[0]^=0xE1;
    return v;
}
static Block polyval_product(const Block& x,const Block& h) {
    // RFC 8452 appendix A: POLYVAL via byte-reversed GHASH with mulX(H).
    Block xrev=reverse_bytes(x), hrev=ghash_times_x(reverse_bytes(h));
    return reverse_bytes(ghash_multiply(xrev,hrev));
}
static void update_polyval(Block& acc,const Block& h,const Bytes& src) {
    for(std::size_t off=0;off<src.size();off+=16) {
        Block b{};
        std::size_t n=std::min<std::size_t>(16,src.size()-off);
        for(std::size_t i=0;i<n;++i)b[i]=src[off+i];
        acc=polyval_product(common::xor_block(acc,b),h);
    }
}
static void put_le64(Block& b,int at,std::uint64_t v) {
    for(int i=0;i<8;++i){b[at+i]=static_cast<Byte>(v);v>>=8;}
}
static std::pair<Block,Bytes> derive(const Bytes& key,const Bytes& nonce) {
    if(key.size()!=16&&key.size()!=32)throw std::invalid_argument("GCM-SIV AES key 16/32 bytes");
    if(nonce.size()!=12)throw std::invalid_argument("GCM-SIV nonce 12 bytes");
    AES aes(key);
    Bytes derived;
    for(unsigned counter=0;counter<(key.size()==16?4U:6U);++counter) {
        Block input{};
        input[0]=static_cast<Byte>(counter);
        for(int i=0;i<12;++i)input[4+i]=nonce[i];
        Block output=aes.encrypt(input);
        derived.insert(derived.end(),output.begin(),output.begin()+8);
    }
    Block auth{};std::copy_n(derived.begin(),16,auth.begin());
    return {auth,Bytes(derived.begin()+16,derived.end())};
}
static Block make_tag(const AES& aes,const Block& h,const Bytes& nonce,const Bytes& plain,const Bytes& aad){
    Block state{};
    update_polyval(state,h,aad);update_polyval(state,h,plain);
    Block lengths{};
    put_le64(lengths,0,static_cast<std::uint64_t>(aad.size())*8);
    put_le64(lengths,8,static_cast<std::uint64_t>(plain.size())*8);
    state=polyval_product(common::xor_block(state,lengths),h);
    for(int i=0;i<12;++i)state[i]^=nonce[i];
    state[15]&=0x7F;
    return aes.encrypt(state);
}
static Bytes ctr_xor(const AES& aes,const Bytes& input,Block counter) {
    counter[15]|=0x80;
    Bytes out;out.reserve(input.size());
    for(std::size_t off=0;off<input.size();off+=16){
        Block stream=aes.encrypt(counter);
        for(std::size_t i=0;i<std::min<std::size_t>(16,input.size()-off);++i)
            out.push_back(static_cast<Byte>(input[off+i]^stream[i]));
        for(int i=0;i<4;++i){if(++counter[i]!=0)break;}
    }
    return out;
}
SivResult gcm_siv_encrypt(const Bytes& key,const Bytes& plain,const Bytes& nonce,const Bytes& aad) {
    auto [h,derived_key]=derive(key,nonce);
    AES aes(derived_key);
    Block tag=make_tag(aes,h,nonce,plain,aad);
    return {ctr_xor(aes,plain,tag),tag};
}
Bytes gcm_siv_decrypt(const Bytes& key,const Bytes& cipher,const Bytes& nonce,const Bytes& aad,const Block& tag){
    auto [h,derived_key]=derive(key,nonce);
    AES aes(derived_key);
    Bytes plain=ctr_xor(aes,cipher,tag);
    Block expected=make_tag(aes,h,nonce,plain,aad);
    unsigned mismatch=0;for(int i=0;i<16;++i)mismatch|=(expected[i]^tag[i]);
    if(mismatch)throw std::invalid_argument("GCM-SIV authentication failed");
    return plain;
}
}
