#include "bn_math.hpp"
#include "task_cli.hpp"
#include "ossl_raii.hpp"
// LAB 3 - TASK A: Số nguyên lớn và các phép toán modulo với OpenSSL BIGNUM.
// Tự xây dựng dựa trên yêu cầu bài tập, không sao chép mã nguồn minh họa của giảng viên.
// Chương trình có menu thực hành và chế độ lệnh để kiểm thử tự động.
// Phần tự cài đặt bình phương - nhân và Euclid mở rộng chỉ phục vụ học tập.

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace task_a {

using namespace std;

using BigNum = unique_ptr<BIGNUM, decltype(&BN_free)>;
using Context = unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

using LabError = lab::Error;

// Tạo đối tượng BIGNUM; unique_ptr tự giải phóng qua BN_free.
BigNum makeNumber() {
    BigNum result(BN_new(), BN_free);
    if (!result) throw runtime_error("Khong cap phat duoc BIGNUM");
    return result;
}

Context makeContext() {
    Context ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) throw runtime_error("Khong cap phat duoc BN_CTX");
    return ctx;
}

void requireOK(int status, const string& operation) {
    if (status != 1) throw LabError(5, "OpenSSL that bai: " + operation + ": " + lab::drainErrors());
}

void copyNumber(BIGNUM* destination, const BIGNUM* source) {
    if (!BN_copy(destination, source))
        throw runtime_error("Sao chep BIGNUM that bai");
}

// Chỉ nhận số thập phân không âm gồm 1..10000 chữ số.
BigNum parseDecimal(const string& input) {
    if (input.empty() || input.size() > 10000 ||
        !all_of(input.begin(), input.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        throw LabError(1, "Du lieu phai la so nguyen khong am, toi da 10000 chu so");
    }
    BIGNUM* raw = nullptr;
    int consumed = BN_dec2bn(&raw, input.c_str());
    if (consumed != static_cast<int>(input.size())) {
        BN_free(raw);
        throw LabError(1, "Khong chuyen duoc so thap phan sang BIGNUM");
    }
    return BigNum(raw, BN_free);
}

string displayNumber(const BIGNUM* number, bool hex = false) {
    char* raw = hex ? BN_bn2hex(number) : BN_bn2dec(number);
    if (!raw) throw runtime_error("Khong chuyen duoc BIGNUM sang chuoi");
    string answer(raw);
    OPENSSL_free(raw);
    return answer;
}

// Các phép toán tách khỏi phần nhập/xuất để dễ kiểm thử và tái sử dụng.
BigNum modOperation(const BIGNUM* a, const BIGNUM* b,
                    const BIGNUM* m, const string& operation) {
    if (BN_is_zero(m)) throw LabError(1, "Modulus m phai >= 1");
    auto result = makeNumber();
    auto ctx = makeContext();
    int ok = 0;
    if (operation == "mod-add")
        ok = BN_mod_add(result.get(), a, b, m, ctx.get());
    else if (operation == "mod-sub")
        ok = BN_mod_sub(result.get(), a, b, m, ctx.get());
    else if (operation == "mod-mul")
        ok = BN_mod_mul(result.get(), a, b, m, ctx.get());
    else if (operation == "mod-exp")
        ok = BN_mod_exp(result.get(), a, b, m, ctx.get());
    else
        throw LabError(1, "Phep toan khong hop le");
    requireOK(ok, operation);
    return result;
}

BigNum greatestCommonDivisor(const BIGNUM* a, const BIGNUM* b) {
    auto result = makeNumber();
    auto ctx = makeContext();
    requireOK(BN_gcd(result.get(), a, b, ctx.get()), "gcd");
    return result;
}

// Lũy thừa modulo theo thuật toán square-and-multiply (chỉ để đối chiếu).
// Không dùng phiên bản này với số mũ bí mật vì có thể rò rỉ thời gian chạy.
BigNum squareAndMultiply(const BIGNUM* a, const BIGNUM* exponent, const BIGNUM* m) {
    if (BN_is_zero(m)) throw LabError(1, "Modulus m phai >= 1");
    auto ctx = makeContext();
    auto result = makeNumber();
    auto base = makeNumber();
    auto remaining = makeNumber();
    auto temporary = makeNumber();
    requireOK(BN_one(result.get()), "Khoi tao gia tri 1");
    requireOK(BN_nnmod(result.get(), result.get(), m, ctx.get()), "Khoi tao modulo");
    requireOK(BN_nnmod(base.get(), a, m, ctx.get()), "Rut gon co so");
    copyNumber(remaining.get(), exponent);

    while (!BN_is_zero(remaining.get())) {
        if (BN_is_odd(remaining.get())) {
            requireOK(BN_mod_mul(temporary.get(), result.get(), base.get(), m, ctx.get()),
                      "Nhan voi co so");
            copyNumber(result.get(), temporary.get());
        }
        requireOK(BN_rshift1(remaining.get(), remaining.get()), "Dich phai so mu");
        if (!BN_is_zero(remaining.get())) {
            requireOK(BN_mod_mul(temporary.get(), base.get(), base.get(), m, ctx.get()),
                      "Binh phuong co so");
            copyNumber(base.get(), temporary.get());
        }
    }
    return result;
}

// Euclid mở rộng: tự tìm nghịch đảo để kiểm tra với BN_mod_inverse.
// Nếu gcd(a,m) != 1, trả về nullptr và ghi gcd vào gcdResult.
BigNum extendedEuclidInverse(const BIGNUM* a, const BIGNUM* m, BIGNUM* gcdResult) {
    auto ctx = makeContext();
    auto oldR = makeNumber();
    auto r = makeNumber();
    auto oldT = makeNumber();
    auto t = makeNumber();
    auto quotient = makeNumber();
    auto product = makeNumber();
    auto next = makeNumber();

    copyNumber(oldR.get(), m);
    requireOK(BN_nnmod(r.get(), a, m, ctx.get()), "Rut gon a");
    BN_zero(oldT.get());
    requireOK(BN_one(t.get()), "Khoi tao he so 1");

    while (!BN_is_zero(r.get())) {
        requireOK(BN_div(quotient.get(), nullptr, oldR.get(), r.get(), ctx.get()), "Euclid chia");
        requireOK(BN_mul(product.get(), quotient.get(), r.get(), ctx.get()), "Euclid nhan r");
        requireOK(BN_sub(next.get(), oldR.get(), product.get()), "Euclid tru r");
        copyNumber(oldR.get(), r.get());
        copyNumber(r.get(), next.get());

        requireOK(BN_mul(product.get(), quotient.get(), t.get(), ctx.get()), "Euclid nhan t");
        requireOK(BN_sub(next.get(), oldT.get(), product.get()), "Euclid tru t");
        copyNumber(oldT.get(), t.get());
        copyNumber(t.get(), next.get());
    }
    copyNumber(gcdResult, oldR.get());
    if (!BN_is_one(oldR.get())) return BigNum(nullptr, BN_free);
    auto inverse = makeNumber();
    requireOK(BN_nnmod(inverse.get(), oldT.get(), m, ctx.get()), "Rut gon nghich dao");
    return inverse;
}

BigNum modularInverse(const BIGNUM* a, const BIGNUM* m) {
    if (BN_cmp(m, BN_value_one()) <= 0)
        throw LabError(1, "Modulus cho nghich dao phai >= 2");
    auto g = greatestCommonDivisor(a, m);
    if (!BN_is_one(g.get())) {
        throw LabError(4, "no inverse: gcd(a,m) = " + displayNumber(g.get()));
    }
    auto ctx = makeContext();
    BigNum inverse(BN_mod_inverse(nullptr, a, m, ctx.get()), BN_free);
    if (!inverse) throw runtime_error("OpenSSL khong tinh duoc nghich dao modulo");
    return inverse;
}

// Chế độ lệnh độc lập: task_a.exe mod-exp 7 13 33 [--hex].
// Mã thoát: 0 thành công, 1 đầu vào sai, 4 không tồn tại nghịch đảo.
int runCommandLine(int argc, char* argv[]) {
    vector<string> args;
    bool hex = false;
    for (int i = 1; i < argc; ++i) {
        if (string(argv[i]) == "--hex") {
            if (hex) throw LabError(1, "--hex chi duoc xuat hien mot lan");
            hex = true;
        } else args.emplace_back(argv[i]);
    }
    if (args.empty()) throw LabError(1, "Thieu ten lenh");
    const string& operation = args[0];
    if (operation == "gcd" && args.size() == 3) {
        auto a = parseDecimal(args[1]);
        auto b = parseDecimal(args[2]);
        cout << displayNumber(greatestCommonDivisor(a.get(), b.get()).get(), hex) << '\n';
    } else if (operation == "mod-inverse" && args.size() == 3) {
        auto a = parseDecimal(args[1]);
        auto m = parseDecimal(args[2]);
        cout << displayNumber(modularInverse(a.get(), m.get()).get(), hex) << '\n';
    } else if ((operation == "mod-add" || operation == "mod-sub" ||
                operation == "mod-mul" || operation == "mod-exp") && args.size() == 4) {
        auto a = parseDecimal(args[1]);
        auto b = parseDecimal(args[2]);
        auto m = parseDecimal(args[3]);
        cout << displayNumber(modOperation(a.get(), b.get(), m.get(), operation).get(), hex) << '\n';
    } else {
        throw LabError(1, "Lenh sai. Dung: mod-add/mod-sub/mod-mul/mod-exp a b m; gcd a b; mod-inverse a m [--hex]");
    }
    return 0;
}

string ask(const string& prompt) {
    cout << prompt << flush;
    string input;
    if (!getline(cin, input)) throw LabError(1, "Da ket thuc du lieu nhap");
    return input;
}

BigNum askNumber(const string& prompt) {
    return parseDecimal(ask(prompt));
}

void printMenu(const BIGNUM* modulus) {
    cout << "\n===== OPENSSL BIGNUM LAB - TASK A =====\n"
         << "Current modulus m: " << displayNumber(modulus) << '\n'
         << "1. Modular addition\n"
         << "2. Modular subtraction\n"
         << "3. Modular multiplication\n"
         << "4. Greatest common divisor\n"
         << "5. Modular exponentiation\n"
         << "6. Modular inverse\n"
         << "7. Generate a large prime for RSA (demo only)\n"
         << "0. Exit\n";
}

int runMenu() {
    cout << "OpenSSL header : " << OPENSSL_VERSION_TEXT << '\n';
    cout << "OpenSSL library: " << OpenSSL_version(OPENSSL_VERSION) << '\n';
    cout << "Nhap m mot lan; gia tri m duoc su dung lai trong cac phep modulo.\n";
    auto modulus = askNumber("Enter modulus m = ");
    if (BN_is_zero(modulus.get())) throw LabError(1, "Modulus m phai >= 1");

    while (true) {
        printMenu(modulus.get());
        string choice = ask("Choose: ");
        if (choice == "0") return 0;
        try {
            if (choice == "1" || choice == "2" || choice == "3" || choice == "5") {
                auto a = askNumber("a = ");
                auto b = askNumber("b = ");
                string operation = choice == "1" ? "mod-add" :
                                   choice == "2" ? "mod-sub" :
                                   choice == "3" ? "mod-mul" : "mod-exp";
                auto result = modOperation(a.get(), b.get(), modulus.get(), operation);
                cout << "Result: " << displayNumber(result.get()) << '\n';
                if (choice == "5") {
                    auto ownResult = squareAndMultiply(a.get(), b.get(), modulus.get());
                    if (BN_cmp(ownResult.get(), result.get()) != 0)
                        throw runtime_error("Square-and-multiply khong khop OpenSSL");
                    cout << "[PASS] Square-and-multiply khop BN_mod_exp\n";
                }
            } else if (choice == "4") {
                auto a = askNumber("a = ");
                auto b = askNumber("b = ");
                auto result = greatestCommonDivisor(a.get(), b.get());
                cout << "Result: " << displayNumber(result.get()) << '\n';
            } else if (choice == "6") {
                auto a = askNumber("a = ");
                if (BN_cmp(modulus.get(), BN_value_one()) <= 0)
                    throw LabError(1, "Modulus cho nghich dao phai >= 2");
                auto gcdResult = makeNumber();
                auto ownInverse = extendedEuclidInverse(a.get(), modulus.get(), gcdResult.get());
                if (!ownInverse) {
                    cout << "no inverse: gcd(a,m) = " << displayNumber(gcdResult.get()) << '\n';
                } else {
                    auto opensslInverse = modularInverse(a.get(), modulus.get());
                    if (BN_cmp(ownInverse.get(), opensslInverse.get()) != 0)
                        throw runtime_error("Euclid mo rong khong khop OpenSSL");
                    cout << "Result: " << displayNumber(opensslInverse.get()) << '\n';
                    cout << "[PASS] Extended Euclid khop BN_mod_inverse\n";
                }
            } else if (choice == "7") {
                string input = ask("Enter prime size in bits (16..8192): ");
                if (input.empty() || input.size() > 4 ||
                    !all_of(input.begin(), input.end(), [](char c) { return c >= '0' && c <= '9'; }))
                    throw LabError(1, "So bit phai trong khoang 16..8192");
                int bits = stoi(input);
                if (bits < 16 || bits > 8192)
                    throw LabError(1, "So bit phai trong khoang 16..8192");
                auto prime = makeNumber();
                auto ctx = makeContext();
                cout << "Dang sinh so nguyen to xac suat " << bits << " bit...\n";
                requireOK(BN_generate_prime_ex2(prime.get(), bits, 0, nullptr,
                                                nullptr, nullptr, ctx.get()), "Sinh so nguyen to");
                cout << "Prime generated successfully.\n";
                cout << "Actual bit length: " << BN_num_bits(prime.get()) << '\n';
                cout << "p = " << displayNumber(prime.get()) << '\n';
                cout << "Chi minh hoa: khong su dung p nay lam khoa RSA thuc te.\n";
            } else {
                cout << "Invalid choice.\n";
            }
        } catch (const exception& error) {
            cerr << "Error: " << error.what() << '\n';
            ERR_clear_error();
        }
    }
}

int entry(int argc, char* argv[]) {
    try {
        if (argc > 1) return runCommandLine(argc, argv);
        return runMenu();
    } catch (const LabError& error) {
        cerr << "Error: " << error.what() << '\n';
        return error.code;
    } catch (const exception& error) {
        cerr << "Error: " << error.what() << '\n';
        return 5;
    }
}

} // namespace task_a
