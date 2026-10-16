#include "sp800_38f.hpp"
#include <limits>
namespace nist {
using Bytes=common::Bytes;
/*
 * SP 800-38F / RFC 3394: AES-KW quấn (wrap) khóa theo các semiblock 8 byte.
 * Thanh ghi A 8 byte lưu giá trị kiểm tra; mỗi bước AES xử lý A||R[i].
 * Đảo ngược 6 vòng quấn để unwrap rồi kiểm tra A == A6...A6.
 */
static Bytes wrap_core(const AES& aes,const Bytes& plain,Bytes a) {
    if(a.size()!=8 || plain.size()<16 || plain.size()%8) throw std::invalid_argument("KW: input phai la boi 8 byte, it nhat 16 byte");
    std::size_t n=plain.size()/8;
    Bytes r=plain;
    for(int j=0;j<6;++j) for(std::size_t i=1;i<=n;++i) {
        Block b{};
        for(int k=0;k<8;++k){b[k]=a[k];b[8+k]=r[(i-1)*8+k];}
        b=aes.encrypt(b);
        a.assign(b.begin(),b.begin()+8);
        std::uint64_t t=static_cast<std::uint64_t>(n)*j+i;
        for(int k=7;k>=0;--k){a[k]^=static_cast<Byte>(t);t>>=8;}
        for(int k=0;k<8;++k)r[(i-1)*8+k]=b[8+k];
    }
    a.insert(a.end(),r.begin(),r.end());
    return a;
}
static std::pair<Bytes,Bytes> unwrap_core(const AES& aes,const Bytes& wrapped) {
    if(wrapped.size()<24||wrapped.size()%8) throw std::invalid_argument("KW: wrapped length khong hop le");
    std::size_t n=wrapped.size()/8-1;
    Bytes a(wrapped.begin(),wrapped.begin()+8),r(wrapped.begin()+8,wrapped.end());
    for(int j=5;j>=0;--j) for(std::size_t i=n;i>=1;--i) {
        Block b{};
        Bytes ax=a;
        std::uint64_t t=static_cast<std::uint64_t>(n)*j+i;
        for(int k=7;k>=0;--k){ax[k]^=static_cast<Byte>(t);t>>=8;}
        for(int k=0;k<8;++k){b[k]=ax[k];b[8+k]=r[(i-1)*8+k];}
        b=aes.decrypt(b);
        a.assign(b.begin(),b.begin()+8);
        for(int k=0;k<8;++k)r[(i-1)*8+k]=b[8+k];
    }
    return {a,r};
}
Bytes kw_wrap(const AES& aes,const Bytes& plain){return wrap_core(aes,plain,Bytes(8,0xA6));}
Bytes kw_unwrap(const AES& aes,const Bytes& wrapped){
    auto [a,r]=unwrap_core(aes,wrapped);
    unsigned diff=0;for(Byte b:a)diff|=(b^0xA6);
    if(diff)throw std::invalid_argument("KW integrity check failed");
    return r;
}
/*
 * RFC 5649 - KWP: cho phép khóa có độ dài không chia hết cho 8.
 * AIV = A65959A6 || độ dài thực 32bit, rồi thêm byte 0 cho đủ semiblock.
 * Nếu chỉ 1 semiblock thì mã hóa trực tiếp AIV||Ppadded bằng AES.
 */
Bytes kwp_wrap(const AES& aes,const Bytes& plain){
    if(plain.empty()||plain.size()>0xffffffffULL)throw std::invalid_argument("KWP input length khong hop le");
    std::uint32_t n=static_cast<std::uint32_t>(plain.size());
    Bytes a={0xA6,0x59,0x59,0xA6,static_cast<Byte>(n>>24),static_cast<Byte>(n>>16),static_cast<Byte>(n>>8),static_cast<Byte>(n)};
    Bytes p=plain;while(p.size()%8)p.push_back(0);
    if(p.size()==8){
        Block b{};for(int i=0;i<8;++i){b[i]=a[i];b[i+8]=p[i];}
        Block c=aes.encrypt(b);return Bytes(c.begin(),c.end());
    }
    return wrap_core(aes,p,a);
}
Bytes kwp_unwrap(const AES& aes,const Bytes& wrapped){
    Bytes a,p;
    if(wrapped.size()==16){
        Block b=aes.decrypt(common::block_at(wrapped,0));
        a.assign(b.begin(),b.begin()+8);p.assign(b.begin()+8,b.end());
    }else{auto result=unwrap_core(aes,wrapped);a=result.first;p=result.second;}
    if(a[0]!=0xA6||a[1]!=0x59||a[2]!=0x59||a[3]!=0xA6)throw std::invalid_argument("KWP AIV incorrect");
    std::uint64_t len=0;for(int i=4;i<8;++i)len=(len<<8)|a[i];
    if(len==0||len>p.size()||len<=p.size()-8)throw std::invalid_argument("KWP encoded length incorrect");
    unsigned bad=0;for(std::size_t i=len;i<p.size();++i)bad|=p[i];
    if(bad)throw std::invalid_argument("KWP padding is not zero");
    p.resize(static_cast<std::size_t>(len));return p;
}
}
