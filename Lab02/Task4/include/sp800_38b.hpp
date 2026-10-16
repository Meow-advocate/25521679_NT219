#pragma once
#include "aes.hpp"
namespace nist { Block cmac(const AES&,const common::Bytes&); }
