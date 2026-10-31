# Lab03 — Task A–E

Bài thực hành gồm năm phần: số học modulo với BIGNUM (Task A), tham số và khóa RSA (Task B), OS2IP/I2OSP và RSA-OAEP (Task C), mã hóa tệp lai RSA-OAEP/AES-256-GCM (Task D), và RSASVE/HKDF/AES-256-GCM (Task E). Các chức năng được gọi từ chương trình dòng lệnh `lab03`.

Repository: https://github.com/Meow-advocate/25521679_NT219/tree/main/Lab03

## Cấu trúc thư mục

| Thư mục hoặc tệp | Nội dung |
|---|---|
| `src/main.cpp` | Nhận lệnh và chuyển tới chức năng tương ứng. |
| `src/task_a.cpp` | Các phép toán với số nguyên lớn và xử lý đầu vào của Task A. |
| `src/task_b.cpp` | Tham số RSA, tạo/đọc/chuyển đổi/kiểm tra khóa. |
| `src/task_c.cpp` | Chuyển đổi giữa byte và số nguyên, thí nghiệm RSA và OAEP. |
| `src/task_d.cpp` | Mã hóa, giải mã tệp bằng phương pháp lai và kiểm tra xác thực. |
| `src/task_e.cpp` | KEM, dẫn xuất khóa và mã hóa/giải mã tệp của Task E. |
| `include/` | Các header công khai dùng để khai báo hàm, kiểu dữ liệu và giao diện giữa các phần. |
| `tests/` | Bộ kiểm thử chấp nhận, kiểm thử giao diện và script thay đổi byte của gói tin. |
| `tests/results/` | Log và kết quả kiểm thử đã ghi lại. |
| `keys/` | Bộ khóa được sinh riêng phục vụ thực hành và kiểm thử. |
| `samples/` | Tệp dữ liệu mẫu dùng khi chạy thử lệnh. |
| `cli_demo/` | Tệp minh họa chạy CLI và kết quả khôi phục. |
| `docs/` | Tệp đối chiếu và kiểm tra tính toàn vẹn đi kèm dự án. |
| `CMakeLists.txt` | Cấu hình biên dịch và khai báo các bài kiểm thử. |
| `build_windows.ps1` | Script biên dịch trên Windows. |
| `.gitignore` | Loại trừ kết quả build và tệp tạm khỏi Git. |
| `25521679.Lab03_TASK(A,B,C,D,E).pdf` | Báo cáo và hình ảnh thực hiện của năm Task. |

## Môi trường thực hiện

- Windows x64; GCC/MinGW-w64 15.2.0; ngôn ngữ C++17.
- CMake 3.20 trở lên; Python 3.12.14 để chạy các bài kiểm thử.
- Tùy chọn biên dịch: `-Wall -Wextra -Wpedantic`.

## Biên dịch

Mở PowerShell tại thư mục `Lab03`, bảo đảm `g++`, `cmake` và `mingw32-make` có trong `PATH`.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\build_windows.ps1
.\build\lab03.exe help
```

Cấu hình build bằng CMake trên Linux:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
./build/lab03 help
```

## Ví dụ các lệnh

Chạy các ví dụ tại thư mục gốc dự án. Trong bảng dưới đây, `lab03` tương ứng với `.\build\lab03.exe` trên Windows hoặc `./build/lab03` trên Linux.

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

Các lệnh số học hỗ trợ `--hex`; `key-convert` hỗ trợ `--inform PEM|DER`. Đối với `rsa-params`, tùy chọn `--show-private` chỉ dùng với khóa học thuật tối đa 1024 bit. Các lệnh mã hóa tệp yêu cầu khóa RSA từ 2048 bit. Cờ `--force` cho phép ghi đè tệp kết quả khi cần.

## Chạy kiểm thử

Sau khi biên dịch:

```powershell
ctest --test-dir build --output-on-failure
.\tests\run_all.ps1
```

Hoặc chạy bộ kiểm thử bằng Python:

```powershell
python tests/run_all.py --exe build/lab03.exe
```

Trên Linux:

```bash
sh tests/run_all --exe build/lab03
```

Các tệp kết quả được ghi tại `tests/results/`:

- `summary.json`: kết quả của từng nhóm kiểm thử.
- `run_all.log`: lệnh thực hiện, dữ liệu đầu ra và mã thoát.

`tests/tamper.py` tạo bản sao của gói tin và thay đổi một byte tại vị trí được chỉ định, ví dụ:

```bash
python tests/tamper.py input.l2pk output.l2pk 0x19e --xor 1
```

Các bài kiểm thử gồm phép toán số nguyên lớn, đọc khóa PEM/DER, mã hóa/giải mã vòng, dữ liệu rỗng và nhị phân, thay đổi header/ciphertext/tag, sai khóa và kiểm tra file đầu ra. Phép thử D-T11 là trao đổi thực tế với nhóm khác; hình ảnh minh chứng được trình bày trong báo cáo, không tính là phép thử tự động.

## Quy ước và lưu ý

- Task A–C phục vụ nghiên cứu các phép toán và tính chất của RSA; Task D–E dùng những giao diện mã hóa dành cho tệp.
- Tệp D/E có giới hạn 1 GiB và xử lý theo khối 64 KiB. Header của gói `L2PK` được đưa vào dữ liệu xác thực (AAD).
- Khi giải mã, kết quả được ghi vào tệp `.part`. Chỉ sau khi kiểm tra tag thành công chương trình mới đổi tên tệp; nếu thất bại, tệp tạm bị xóa.
- Task E sử dụng profile `LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1`, với `key_id` gắn khóa dẫn xuất với khóa người nhận.
- Mã thoát: `0` thành công; `1` đầu vào; `2` I/O; `3` định dạng; `4` xác thực/mật mã; `5` lỗi nội bộ.
- Bộ khóa trong `keys/` chỉ dùng cho bài thực hành và kiểm thử. Không sử dụng khóa cá nhân hoặc khóa đang triển khai thực tế.
