#include "sp800_38c.hpp"
#include <algorithm>
#include <limits>
namespace nist {
using Bytes=common::Bytes;
/*
 * SP 800-38C - CCM: mã hóa CTR và tính tag CBC-MAC trên P (plaintext), AAD.
 * B0 = flags || nonce || length(P); tag được XOR với AES(counter=0).
 * Giải mã phải kiểm chứng tag trước khi TRẢ plaintext cho người dùng.
 */
static Bytes make_counter(const Bytes& nonce,std::uint64_t counter) {
    const int L=15-static_cast<int>(nonce.size());
    Block b{};b[0]=static_cast<Byte>(L-1);
    for(std::size_t i=0;i<nonce.size();++i) b[1+i]=nonce[i];
    for(int i=0;i<L;++i) { b[15-i]=static_cast<Byte>(counter & 255); counter>>=8; }
    return Bytes(b.begin(),b.end());
}
static Bytes counter_xor(const AES& aes,const Bytes& data,const Bytes& nonce) {
    Bytes result;result.reserve(data.size());
    for(std::size_t i=0;i<data.size();i+=16) {
        std::size_t index=i/16+1;
        Block stream=aes.encrypt(common::block_at(make_counter(nonce,index),0));
        for(std::size_t j=0;j<std::min<std::size_t>(16,data.size()-i);++j) result.push_back(data[i+j]^stream[j]);
    }
    return result;
}
static void add_aad_length(Bytes& buffer,std::size_t n) {
    if(n<0xff00) {buffer.push_back(static_cast<Byte>(n>>8));buffer.push_back(static_cast<Byte>(n));}
    else if(n<=0xffffffffULL) {buffer.insert(buffer.end(),{0xff,0xfe});for(int j=3;j>=0;--j) buffer.push_back(static_cast<Byte>(n>>(8*j)));}
    else {buffer.insert(buffer.end(),{0xff,0xff});for(int j=7;j>=0;--j) buffer.push_back(static_cast<Byte>(n>>(8*j)));}
}
static Block compute_tag(const AES& aes,const Bytes& plain,const Bytes& nonce,const Bytes& aad,int taglen) {
    int L=15-static_cast<int>(nonce.size());
    Block b0{};
    b0[0]=static_cast<Byte>((aad.empty()?0:0x40) | (((taglen-2)/2)<<3) | (L-1));
    for(std::size_t i=0;i<nonce.size();++i) b0[i+1]=nonce[i];
    std::uint64_t count=static_cast<std::uint64_t>(plain.size());
    for(int j=0;j<L;++j) {b0[15-j]=static_cast<Byte>(count&255);count>>=8;}
    if(count) throw std::invalid_argument("CCM: qua gioi han plaintext theo L");
    Bytes formatted;
    common::append(formatted,b0);
    if(!aad.empty()) {
        add_aad_length(formatted,aad.size());
        formatted.insert(formatted.end(),aad.begin(),aad.end());
        while(formatted.size()%16) formatted.push_back(0);
    }
    formatted.insert(formatted.end(),plain.begin(),plain.end());
    while(formatted.size()%16) formatted.push_back(0);
    Block state{};
    for(std::size_t off=0;off<formatted.size();off+=16)
        state=aes.encrypt(common::xor_block(state,common::block_at(formatted,off)));
    return common::xor_block(state,aes.encrypt(common::block_at(make_counter(nonce,0),0)));
}
static void validate(const Bytes& nonce,int taglen) {
    if(nonce.size()<7 || nonce.size()>13) throw std::invalid_argument("CCM: nonce 7..13 byte");
    if(taglen<4||taglen>16||taglen%2) throw std::invalid_argument("CCM: taglen chan 4..16");
}
CcmResult ccm_encrypt(const AES& aes,const Bytes& plain,const Bytes& nonce,const Bytes& aad,int taglen) {
    validate(nonce,taglen);
    Block mac=compute_tag(aes,plain,nonce,aad,taglen);
    return {counter_xor(aes,plain,nonce),Bytes(mac.begin(),mac.begin()+taglen)};
}
Bytes ccm_decrypt(const AES& aes,const Bytes& cipher,const Bytes& nonce,const Bytes& aad,const Bytes& tag) {
    validate(nonce,static_cast<int>(tag.size()));
    Bytes plain=counter_xor(aes,cipher,nonce);
    Block expected=compute_tag(aes,plain,nonce,aad,static_cast<int>(tag.size()));
    unsigned diff=0;for(std::size_t i=0;i<tag.size();++i) diff |= (tag[i]^expected[i]);
    if(diff) throw std::invalid_argument("CCM: tag sai, tu choi giai ma");
    return plain;
}
}
