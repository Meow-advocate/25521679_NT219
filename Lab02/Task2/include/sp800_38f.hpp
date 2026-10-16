#pragma once
#include "aes.hpp"
namespace nist {
common::Bytes kw_wrap(const AES&,const common::Bytes&);
common::Bytes kw_unwrap(const AES&,const common::Bytes&);
common::Bytes kwp_wrap(const AES&,const common::Bytes&);
common::Bytes kwp_unwrap(const AES&,const common::Bytes&);
}
