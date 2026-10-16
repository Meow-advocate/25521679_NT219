#include <jni.h>
#include "aes_c_api.h"
#include <cstdint>
#include <vector>

/*
 * JNI bridge: đổi byte[] Java thành dãy byte C++, gọi đúng C API của thư viện AES,
 * rồi trả lại byte[] cho Java. Mọi lỗi đều chuyển thành Java exception.
 */
static jbyteArray call_aes(JNIEnv* env, jbyteArray key, jbyteArray input, bool decrypt) {
    if (!key || !input) {
        jclass ex = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(ex, "key/input is null");
        return nullptr;
    }
    const jsize key_length = env->GetArrayLength(key);
    const jsize input_length = env->GetArrayLength(input);
    if ((key_length != 16 && key_length != 24 && key_length != 32) || input_length != 16) {
        jclass ex = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(ex, "key must be 16/24/32 bytes and block must be 16 bytes");
        return nullptr;
    }
    try {
        std::vector<uint8_t> key_data(static_cast<size_t>(key_length));
        std::vector<uint8_t> input_data(16);
        env->GetByteArrayRegion(key, 0, key_length, reinterpret_cast<jbyte*>(key_data.data()));
        if (env->ExceptionCheck()) return nullptr;
        env->GetByteArrayRegion(input, 0, 16, reinterpret_cast<jbyte*>(input_data.data()));
        if (env->ExceptionCheck()) return nullptr;
        uint8_t result[16]{};
        int status = decrypt
            ? aes_decrypt_block(key_data.data(), key_length, input_data.data(), 16, result, 16)
            : aes_encrypt_block(key_data.data(), key_length, input_data.data(), 16, result, 16);
        if (status != 0) {
            jclass ex = env->FindClass("java/lang/IllegalStateException");
            env->ThrowNew(ex, "C++ AES call failed");
            return nullptr;
        }
        jbyteArray output = env->NewByteArray(16);
        if (!output) return nullptr;
        env->SetByteArrayRegion(output, 0, 16, reinterpret_cast<jbyte*>(result));
        return output;
    } catch (...) {
        jclass ex = env->FindClass("java/lang/IllegalStateException");
        env->ThrowNew(ex, "Unexpected error inside JNI bridge");
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_AESJavaDemo_nativeEncrypt
  (JNIEnv* env, jclass, jbyteArray key, jbyteArray data) {
    return call_aes(env, key, data, false);
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_AESJavaDemo_nativeDecrypt
  (JNIEnv* env, jclass, jbyteArray key, jbyteArray data) {
    return call_aes(env, key, data, true);
}
