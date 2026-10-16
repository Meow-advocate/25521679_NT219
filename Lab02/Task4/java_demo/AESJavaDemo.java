import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

/*
 * Task 4: Java gọi thư viện C++ qua JNI, không tự viết thuật toán AES bằng Java.
 * Để dễ tìm DLL/SO, truyền đường dẫn thư mục build làm tham số thứ nhất.
 */
public class AESJavaDemo {
    private static native byte[] nativeEncrypt(byte[] key, byte[] plaintext);
    private static native byte[] nativeDecrypt(byte[] key, byte[] ciphertext);

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java AESJavaDemo <absolute build directory>");
            System.exit(2);
        }
        String extension = System.getProperty("os.name").toLowerCase().contains("win") ? ".dll" : ".so";
        String prefix = extension.equals(".dll") ? "" : "lib";
        Path dir = Path.of(args[0]).toAbsolutePath();
        System.load(dir.resolve(prefix + "aes_c_api" + extension).toString());
        System.load(dir.resolve(prefix + "aes_jni" + extension).toString());

        HexFormat hex = HexFormat.of();
        byte[] key = hex.parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] plain = hex.parseHex("00112233445566778899aabbccddeeff");
        byte[] expected = hex.parseHex("69c4e0d86a7b0430d8cdb78070b4c55a");
        byte[] cipher = nativeEncrypt(key, plain);
        byte[] back = nativeDecrypt(key, cipher);
        boolean encOK = Arrays.equals(cipher, expected);
        boolean decOK = Arrays.equals(back, plain);
        System.out.println("Java JNI -> C++ AES shared library");
        System.out.println("Ciphertext: " + hex.formatHex(cipher));
        System.out.println("Encrypt: " + (encOK ? "PASS" : "FAIL"));
        System.out.println("Decrypt: " + (decOK ? "PASS" : "FAIL"));
        if (!encOK || !decOK) System.exit(1);
    }
}
