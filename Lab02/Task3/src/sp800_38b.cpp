#include "sp800_38b.hpp"
#include <algorithm>
namespace nist {
/*
 * SP 800-38B - CMAC (không phải một mode mã hóa).
 * Sinh hai subkey K1/K2 từ AES(0), chọn khóa theo block cuối có đủ 16 byte hay không.
 * Các block trước cùng thao tác CBC-MAC, kết quả cuối là tag 128-bit.
 */
static Block double_gf128(Block value) {
    const bool carry = (value[0] & 0x80) != 0;
    for(int i=0;i<16;++i) {
        Byte next = i==15?0:value[i+1];
        value[i] = static_cast<Byte>((value[i] << 1) | (next >> 7));
    }
    if(carry) value[15] ^= 0x87;
    return value;
}
Block cmac(const AES& aes,const common::Bytes& message) {
    Block L = aes.encrypt(Block{});
    Block K1 = double_gf128(L), K2 = double_gf128(K1);
    std::size_t n = message.empty()?1:((message.size()+15)/16);
    bool complete = !message.empty() && message.size()%16 == 0;
    Block state{};
    for(std::size_t j=0;j+1<n;++j) {
        Block input=common::block_at(message,j*16);
        state=aes.encrypt(common::xor_block(state,input));
    }
    Block last{};
    std::size_t offset=(n-1)*16;
    std::size_t len=message.size()-offset;
    for(std::size_t j=0;j<len;++j) last[j]=message[offset+j];
    if(!complete) last[len]=0x80;
    last=common::xor_block(last,complete?K1:K2);
    return aes.encrypt(common::xor_block(state,last));
}
} // namespace nist
