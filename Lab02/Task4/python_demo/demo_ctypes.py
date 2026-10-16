"""Task 4: Python gọi C++ AES bằng ctypes; không dùng thư viện mã hóa Python."""
import ctypes
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = Path(os.getenv('AES_BUILD_DIR', str(ROOT / 'build-gcc')))
LIB_FILE = BUILD_DIR / ('aes_c_api.dll' if sys.platform == 'win32' else 'libaes_c_api.so')
if not LIB_FILE.is_file():
    raise SystemExit(f'Khong tim thay {LIB_FILE}\nHay build CMake truoc.')

# MinGW DLL có thể phụ thuộc runtime của MSYS2 UCRT64 trên Windows.
_dll_dirs = []
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    mingw_bin = Path('C:/msys64/ucrt64/bin')
    if mingw_bin.is_dir():
        _dll_dirs.append(os.add_dll_directory(str(mingw_bin)))
lib = ctypes.CDLL(str(LIB_FILE))
ByteArray = ctypes.POINTER(ctypes.c_uint8)
for func in (lib.aes_encrypt_block, lib.aes_decrypt_block):
    func.argtypes = [ByteArray, ctypes.c_int, ByteArray, ctypes.c_int, ByteArray, ctypes.c_int]
    func.restype = ctypes.c_int


def call_aes(function, key: bytes, data: bytes) -> bytes:
    key_array = (ctypes.c_uint8 * len(key)).from_buffer_copy(key)
    data_array = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    out_array = (ctypes.c_uint8 * 16)()
    status = function(key_array, len(key), data_array, len(data), out_array, len(out_array))
    if status != 0:
        raise ValueError(f'C++ tra ma loi: {status}')
    return bytes(out_array)


key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
expected = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
ciphertext = call_aes(lib.aes_encrypt_block, key, plaintext)
recovered = call_aes(lib.aes_decrypt_block, key, ciphertext)
print('Python ctypes -> C++ AES shared library')
print('Ciphertext:', ciphertext.hex())
print('Encrypt:', 'PASS' if ciphertext == expected else 'FAIL')
print('Decrypt:', 'PASS' if recovered == plaintext else 'FAIL')
sys.exit(0 if ciphertext == expected and recovered == plaintext else 1)
