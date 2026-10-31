# Lab03 CLI — Task A–E

Mã nguồn được phát triển từ năm tệp C++ trong bản ZIP người học cung cấp. Bản này bổ sung thư viện `labcore`, header công khai, đọc khóa dùng chung, phân loại lỗi, bảo vệ bộ đệm bí mật và bộ kiểm thử độc lập. Không nhập mã C++ mẫu từ hai PDF của giảng viên. Tên lệnh, định dạng byte, nhãn KDF và vector kiểm thử giữ đúng đặc tả; đó là yêu cầu tương thích, không phải mã nguồn sao chép.

## Môi trường đã kiểm tra

- Windows x64; GCC/MinGW-w64 15.2.0; C++17.
- OpenSSL 4.1.0-beta1, build ngày 23 Sep 2026, liên kết `libcrypto` tĩnh trong lần kiểm tra này.
- CMake >= 3.20; Python 3.12.14; cryptography 50.0.2 cho kiểm chứng độc lập định dạng Task D.
- Cờ biên dịch: `-Wall -Wextra -Wpedantic`; bản Release đã build sạch không có cảnh báo.
- Nguồn yêu cầu OpenSSL >= 3.0 có provider RSA/RSASVE/HKDF. Chưa xác nhận chạy trên mọi phiên bản OpenSSL hay hệ điều hành khác.

## Build

Thêm `g++`, `cmake`, `mingw32-make` và `openssl` vào PATH. Trên Windows PowerShell:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="D:/cryptolibrary/openssl-4.1.0-beta1/gcc" -DOPENSSL_USE_STATIC_LIBS=TRUE
cmake --build build --parallel 4
.\build\lab03.exe version
```

Nếu máy có nhiều bộ GCC, truyền thêm `-DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe`. `mingw32-make` cũng phải nằm trong PATH, hoặc truyền đường dẫn qua `-DCMAKE_MAKE_PROGRAM=...`. Đường dẫn OpenSSL ở trên là môi trường đã dùng, cần thay theo máy chấm.

Linux/macOS (chưa chạy trong lần kiểm tra này):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

Kiểm thử cần `python -m pip install cryptography`; khi có nhiều Python, truyền `-DPython3_EXECUTABLE=...` vào lệnh CMake. Không cần Python để chạy chương trình CLI đã biên dịch.

## Ví dụ cho từng lệnh

Chạy tại gốc project. Thay `lab03` bằng `.\build\lab03.exe` trên Windows hoặc `./build/lab03` trên POSIX.

| Lệnh | Ví dụ |
|---|---|
| help | `lab03 help` |
| version | `lab03 version` |
| mod-add | `lab03 mod-add 18446744073709551615 1 18446744073709551629` |
| mod-sub | `lab03 mod-sub 3 5 7` |
| mod-mul | `lab03 mod-mul 7 13 33` |
| mod-exp | `lab03 mod-exp 7 13 33` |
| gcd | `lab03 gcd 252 105` |
| mod-inverse | `lab03 mod-inverse 7 33` |
| rsa-params | `lab03 rsa-params --bits 512` |
| keygen | `lab03 keygen --bits 3072 --out-dir keys --force` |
| key-convert | `lab03 key-convert --type public --in keys/public.pem --out converted.der --outform DER` |
| key-info | `lab03 key-info --pub keys/public.pem` |
| key-check | `lab03 key-check --priv keys/private.pem --pub keys/public.der` |
| os2ip | `lab03 os2ip --hex 00ff00` |
| i2osp | `lab03 i2osp --int 65280 --len 3` |
| raw-rsa | `lab03 raw-rsa --bits 512` |
| oaep-demo | `lab03 oaep-demo --pub keys/public.pem --priv keys/private.pem` |
| encrypt | `lab03 encrypt --pub keys/public.pem --in samples/message.txt --out sample-d.l2pk` |
| decrypt | `lab03 decrypt --priv keys/private.pem --in sample-d.l2pk --out recovered-d.txt` |
| kem-encrypt | `lab03 kem-encrypt --pub keys/public.pem --in samples/message.txt --out sample-e.l2pk` |
| kem-decrypt | `lab03 kem-decrypt --priv keys/private.pem --in sample-e.l2pk --out recovered-e.txt` |
| kem-selftest | `lab03 kem-selftest --pub keys/public.pem --priv keys/private.pem` |
| task-c-all | `lab03 task-c-all` |
| task-d-all | `lab03 task-d-all` |

Các lệnh số học hỗ trợ `--hex`. `key-convert` hỗ trợ `--inform PEM|DER`. `rsa-params --show-private` chỉ hiển thị tham số của khóa học thuật <=1024 bit. Mọi lệnh bảo mật yêu cầu RSA >=2048 bit. `--force` chỉ dùng khi chủ động thay thế kết quả; không dùng chung đường dẫn đầu vào và đầu ra.

## Kiểm thử

```powershell
ctest --test-dir build --output-on-failure
# Hoặc
python tests/run_all.py --exe build/lab03.exe --openssl openssl
# Hoặc
.\tests\run_all.ps1 -Python python -OpenSSL openssl
```

POSIX: `sh tests/run_all --exe build/lab03 --openssl openssl`.

- `tests/results/summary.json`: kết quả từng nhóm, số kiểm tra và thời gian.
- `tests/results/run_all.log`: lệnh, stdout, stderr và mã thoát thực tế; không ghi bí mật chung hay khóa AES.
- `tests/results/ctest.log`: hai bài kiểm thử CTest.
- `tests/tamper.py input.l2pk output.l2pk 0x19e --xor 1`: sửa một byte trên bản sao; không ghi đè bản gốc.
- Bộ test dùng Python số nguyên lớn để kiểm tra độc lập Task A; dùng OpenSSL CLI và Python AESGCM để kiểm chứng hai chiều định dạng Task D. Tệp đầu vào gồm rỗng, UTF-8, PDF, ZIP, PNG và nhị phân 50 MiB.
- KEM selftest kiểm tra EVP 100 vòng, trao đổi EVP/edu hai chiều, RFC 5869 KAT và đổi nhãn KDF. Test ngoài CLI kiểm tra PEM/DER, parser và trường hợp sửa dữ liệu.
- D-T11: theo yêu cầu người học, không kiểm chứng lại với nhóm Hà. Ảnh trao đổi thủ công có sẵn được giữ trong báo cáo; kết quả này được ghi `SKIPPED-USER-REQUEST`, không tính thành test tự động PASS. Kiểm chứng OpenSSL độc lập có nhãn riêng `D-INTEROP-REFERENCE`.

## Cấu trúc và giới hạn

`src/main.cpp` chỉ điều phối lệnh; các hàm xử lý nằm trong `labcore`. `include/bn_math.hpp`, `rsa_params.hpp`, `rsa_encoding.hpp`, `key_io.hpp`, `rsa_kem.hpp`, `ossl_raii.hpp`, `task_cli.hpp` là các interface của bản triển khai này. Task C dùng RSA không đệm trong nhánh học thuật; `encrypt`, `decrypt`, `kem-encrypt`, `kem-decrypt` không gọi RSA học thuật. D/E dùng cùng loader SPKI/PKCS#8 của Task B.

Giới hạn số nguyên thập phân: 10000 chữ số; OS2IP/I2OSP: 1024 byte; khóa đầu vào: 1 MiB; tệp D/E: 1 GiB; xử lý theo khối 64 KiB. Header L2PK được đưa trọn vẹn vào AAD. Bản rõ tạm được ghi vào `<out>.part`, chỉ đổi tên sau khi tag hợp lệ; lỗi xóa tệp tạm và giữ nguyên kết quả cũ. Lỗi OAEP/GCM chung là `decryption failed`, exit 4.

Task E dùng profile `LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1`, không tuyên bố là RSA-KEM RFC 9690. `key_id` sai trả exit 4 và thông báo chung; lỗi cấu trúc/ciphertext ngoài miền trả exit 3. Mã thoát: 0 thành công, 1 cú pháp/đầu vào, 2 I/O, 3 định dạng, 4 mật mã, 5 nội bộ.

Khóa trong `keys/` chỉ phục vụ chấm bài và được chương trình sinh trong lần chạy bộ test. PKCS#8 không mã hóa không dùng cho hệ thống thực. POSIX tạo tệp khóa riêng 0600. Windows dùng ACL kế thừa của thư mục; bản CLI không tự thay đổi DACL. Chạy trong thư mục chỉ tài khoản hiện tại được truy cập; có thể dùng `icacls` để kiểm tra quyền. Không dùng khóa cá nhân/khóa triển khai thật với bộ test.

Báo cáo đi kèm giữ nguyên các ảnh và khối code thực hành ban đầu; phần CLI sau Task E và kết quả trong ZIP tương ứng bản tích hợp cuối. Các thay đổi mã giữa bản thực hành và bản CLI được ghi trong `docs/CHANGES.md`.
