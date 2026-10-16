#include "sp800_38e.hpp"
#include <algorithm>
namespace nist {
using Bytes=common::Bytes;
/*
 * SP 800-38E - XTS: dùng hai khóa AES độc lập (data / tweak).
 * Tweak = AES_K2(data_unit_number), mỗi block tiếp theo nhân alpha trong GF(2^128).
 * Khi block cuối thiếu byte, ciphertext stealing (CTS) hoán đổi byte giữa hai block cuối.
 */
static Block tweak_times_alpha(Block t) {
    bool carry=false;
    for(int i=0;i<16;++i) {
        bool n=(t[i]&0x80)!=0;
        t[i]=static_cast<Byte>((t[i]<<1)|(carry?1:0));
        carry=n;
    }
    if(carry)t[0]^=0x87;
    return t;
}
static Bytes xts_process(const Bytes& keys,const Bytes& input,const Block& data_unit,bool encrypt) {
    if(keys.size()!=32 && keys.size()!=64) throw std::invalid_argument("XTS: tong khoa phai 32/64 byte");
    if(input.size()<16) throw std::invalid_argument("XTS: mot don vi du lieu it nhat 16 byte");
    const std::size_t half=keys.size()/2;
    AES aes1(Bytes(keys.begin(),keys.begin()+half)),aes2(Bytes(keys.begin()+half,keys.end()));
    Block tweak=aes2.encrypt(data_unit);
    auto crypt_block=[&](const Block& in,const Block& mask) {
        Block x=common::xor_block(in,mask);
        Block y=encrypt?aes1.encrypt(x):aes1.decrypt(x);
        return common::xor_block(y,mask);
    };
    std::size_t whole=input.size()/16, tail=input.size()%16;
    Bytes output;output.reserve(input.size());
    std::size_t normal=whole-(tail?1:0);
    for(std::size_t j=0;j<normal;++j) {
        common::append(output,crypt_block(common::block_at(input,j*16),tweak));
        tweak=tweak_times_alpha(tweak);
    }
    if(!tail)return output;
    Block next_tweak=tweak_times_alpha(tweak);
    if(encrypt) {
        Block last_full=common::block_at(input,normal*16);
        Block stolen=crypt_block(last_full,tweak);
        Block padded{};
        for(std::size_t j=0;j<tail;++j)padded[j]=input[(normal+1)*16+j];
        for(std::size_t j=tail;j<16;++j)padded[j]=stolen[j];
        common::append(output,crypt_block(padded,next_tweak));
        output.insert(output.end(),stolen.begin(),stolen.begin()+tail);
    } else {
        Block full_cipher=common::block_at(input,normal*16);
        Block recovered=crypt_block(full_cipher,next_tweak);
        Block stolen{};
        for(std::size_t j=0;j<tail;++j)stolen[j]=input[(normal+1)*16+j];
        for(std::size_t j=tail;j<16;++j)stolen[j]=recovered[j];
        common::append(output,crypt_block(stolen,tweak));
        output.insert(output.end(),recovered.begin(),recovered.begin()+tail);
    }
    return output;
}
Bytes xts_encrypt(const Bytes& key,const Bytes& p,const Block& tweak) {return xts_process(key,p,tweak,true);}
Bytes xts_decrypt(const Bytes& key,const Bytes& c,const Block& tweak) {return xts_process(key,c,tweak,false);}
}
