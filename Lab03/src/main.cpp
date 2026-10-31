#include "task_cli.hpp"
// Giao diện dòng lệnh chung cho các phần thực hành.
#include <openssl/crypto.h>
#include <iostream>
#include <string>
#include <vector>

namespace task_a { int entry(int argc, char** argv); }
namespace task_b { int entry(int argc, char** argv); }
namespace task_c { int entry(int argc, char** argv); }
namespace task_d { int entry(int argc, char** argv); }
namespace task_e { int entry(int argc, char** argv); }

namespace {
void usage() {
    std::cout
        << "Lab03 - OpenSSL RSA/KEM\n"
        << "Cac lenh:\n"
        << "  mod-add <a> <b> <m> | mod-sub <a> <b> <m>\n"
        << "  mod-mul <a> <b> <m> | mod-exp <a> <b> <m>\n"
        << "  gcd <a> <b> | mod-inverse <a> <m>\n"
        << "  rsa-params --bits <128..1024> [--show-private]\n"
        << "  keygen --bits <2048|3072|4096> --out-dir <dir>\n"
        << "  key-convert --type public|private --in <key> --out <key> --outform PEM|DER\n"
        << "  key-info --pub <key> | key-check --priv <key> --pub <key>\n"
        << "  os2ip --hex <hex> | i2osp --int <n> --len <L>\n"
        << "  raw-rsa --bits <512..1024> | oaep-demo --pub <key> --priv <key>\n"
        << "  encrypt --pub <key> --in <file> --out <l2pk> [--force]\n"
        << "  decrypt --priv <key> --in <l2pk> --out <file> [--force]\n"
        << "  kem-selftest --pub <key> --priv <key>\n"
        << "  kem-encrypt --pub <key> --in <file> --out <l2pk> [--force]\n"
        << "  kem-decrypt --priv <key> --in <l2pk> --out <file> [--force]\n"
        << "  task-c-all | task-d-all\n"
        << "  lab03 help | lab03 version | lab03 <lenh> --help\n";
}

bool matches(const std::string& command, std::initializer_list<const char*> options) {
    for (const char* option : options) if (command == option) return true;
    return false;
}
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const std::string cmd(argv[1]);
    if (cmd == "help" || cmd == "--help") { usage(); return 0; }
    if (cmd == "version") { std::cout << "Linked OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << '\n'; return 0; }
    if (argc == 3 && std::string(argv[2]) == "--help") { usage(); return 0; }
    if (matches(cmd,{"mod-add","mod-sub","mod-mul","mod-exp","gcd","mod-inverse"}))
        return task_a::entry(argc,argv);
    if (matches(cmd,{"rsa-params","keygen","key-convert","key-info","key-check"}))
        return task_b::entry(argc,argv);
    if (matches(cmd,{"os2ip","i2osp","raw-rsa","oaep-demo"}))
        return task_c::entry(argc,argv);
    if (matches(cmd,{"encrypt","decrypt"})) return task_d::entry(argc,argv);
    if (matches(cmd,{"kem-selftest","kem-encrypt","kem-decrypt"})) return task_e::entry(argc,argv);
    if (cmd == "task-c-all") {
        char arg[] = "--all-full";
        char* local[] = {argv[0],arg,nullptr};
        return task_c::entry(2,local);
    }
    if (cmd == "task-d-all") {
        char arg[] = "--all";
        char* local[] = {argv[0],arg,nullptr};
        return task_d::entry(2,local);
    }
    std::cerr << "Khong tim thay lenh: " << cmd << '\n';
    usage();
    return 1;
}
