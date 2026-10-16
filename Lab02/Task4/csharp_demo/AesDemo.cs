using System;
using System.IO;
using System.Runtime.InteropServices;

/*
 * Task 4 mở rộng: C# P/Invoke cùng thư viện AES C++ mà Python đang gọi.
 * Chạy trong thư mục build có aes_c_api.dll trên Windows.
 * Yêu cầu .NET SDK; không sử dụng thư viện mật mã .NET.
 */
class AesDemo {
    [DllImport("aes_c_api", CallingConvention = CallingConvention.Cdecl)]
    private static extern int aes_encrypt_block(byte[] key, int keyLen,
        byte[] input, int inputLen, byte[] output, int outputCapacity);

    [DllImport("aes_c_api", CallingConvention = CallingConvention.Cdecl)]
    private static extern int aes_decrypt_block(byte[] key, int keyLen,
        byte[] input, int inputLen, byte[] output, int outputCapacity);

    static int Main() {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        byte[] plain = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] expected = Convert.FromHexString("69c4e0d86a7b0430d8cdb78070b4c55a");
        byte[] cipher = new byte[16], back = new byte[16];
        int a = aes_encrypt_block(key, key.Length, plain, plain.Length, cipher, cipher.Length);
        int b = aes_decrypt_block(key, key.Length, cipher, cipher.Length, back, back.Length);
        bool okEnc = a == 0 && Convert.ToHexString(cipher) == Convert.ToHexString(expected);
        bool okDec = b == 0 && Convert.ToHexString(back) == Convert.ToHexString(plain);
        Console.WriteLine("C# P/Invoke -> C++ AES shared library");
        Console.WriteLine("Ciphertext: " + Convert.ToHexString(cipher).ToLowerInvariant());
        Console.WriteLine("Encrypt: " + (okEnc ? "PASS" : "FAIL"));
        Console.WriteLine("Decrypt: " + (okDec ? "PASS" : "FAIL"));
        return okEnc && okDec ? 0 : 1;
    }
}
