#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <unordered_map>

#include "jni.h"
#include <jvmti.h>
#include <jni_md.h>
#include "com_seaboat_bytecode_ByteCodeEncryptor.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace {

static const size_t HEADER_LEN = 4;
static const size_t NONCE_LEN = 12;
static const size_t TAG_LEN = 16;
static const unsigned char MAGIC[4] = { 'B', 'C', 'E', 'K' };

static std::unordered_map<std::string, std::vector<unsigned char>> g_class_cache;

static std::string get_env_key() {
    const char* env_key = std::getenv("BYTECODE_KEY");
    if (env_key != nullptr && env_key[0] != '\0') {
        return std::string(env_key);
    }
    return "ByteCodeEncryptor-Production-Key-2026";
}

static std::vector<unsigned char> derive_key(const std::string& class_name) {
    std::string seed = get_env_key() + ":" + class_name;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(seed.data()), seed.size(), hash);

    std::vector<unsigned char> key(32, 0);
    for (size_t i = 0; i < 32; ++i) {
        key[i] = hash[i % SHA256_DIGEST_LENGTH];
    }
    return key;
}

static bool should_decrypt_class(const char* name) {
    if (name == nullptr) {
        return false;
    }

    std::string n(name);
    return n.rfind("com/seaboat/", 0) == 0 ||
           n.rfind("cn/zzp/", 0) == 0;
}

static void random_nonce(unsigned char out[NONCE_LEN]) {
    if (RAND_bytes(out, NONCE_LEN) != 1) {
        for (size_t i = 0; i < NONCE_LEN; ++i) {
            out[i] = static_cast<unsigned char>((i + 7) * 17);
        }
    }
}

static std::vector<unsigned char> encrypt_buffer(const unsigned char* in, size_t in_len, const std::string& class_name) {
    if (in == nullptr || in_len == 0) {
        return {};
    }

    std::vector<unsigned char> key = derive_key(class_name);
    unsigned char nonce[NONCE_LEN];
    random_nonce(nonce);

    size_t total_capacity = HEADER_LEN + NONCE_LEN + in_len + TAG_LEN + 32;
    std::vector<unsigned char> out(total_capacity, 0);

    std::memcpy(out.data(), MAGIC, HEADER_LEN);
    std::memcpy(out.data() + HEADER_LEN, nonce, NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return {};
    }

    int out_len = 0;
    int final_len = 0;

    int ok = 1;
    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);
    ok = ok && EVP_EncryptUpdate(ctx,
                                 out.data() + HEADER_LEN + NONCE_LEN,
                                 &out_len,
                                 in,
                                 static_cast<int>(in_len));
    ok = ok && EVP_EncryptFinal_ex(ctx,
                                   out.data() + HEADER_LEN + NONCE_LEN + out_len,
                                   &final_len);

    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    unsigned char tag[TAG_LEN];
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        return {};
    }

    std::memcpy(out.data() + HEADER_LEN + NONCE_LEN + out_len + final_len, tag, TAG_LEN);
    size_t total_size = HEADER_LEN + NONCE_LEN + static_cast<size_t>(out_len + final_len) + TAG_LEN;
    out.resize(total_size);
    return out;
}

static std::vector<unsigned char> decrypt_buffer(const unsigned char* in, size_t in_len, const std::string& class_name) {
    if (in == nullptr || in_len < HEADER_LEN + NONCE_LEN + TAG_LEN) {
        return {};
    }

    if (std::memcmp(in, MAGIC, HEADER_LEN) != 0) {
        return {};
    }

    size_t ciphertext_len = in_len - HEADER_LEN - NONCE_LEN - TAG_LEN;
    if (ciphertext_len == 0) {
        return {};
    }

    const unsigned char* nonce = in + HEADER_LEN;
    const unsigned char* ciphertext = in + HEADER_LEN + NONCE_LEN;
    const unsigned char* tag = in + in_len - TAG_LEN;

    std::vector<unsigned char> key = derive_key(class_name);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return {};
    }

    std::vector<unsigned char> out(ciphertext_len, 0);

    int out_len = 0;
    int final_len = 0;

    int ok = 1;
    ok = ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);
    ok = ok && EVP_DecryptUpdate(ctx, out.data(), &out_len, ciphertext, static_cast<int>(ciphertext_len));
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<unsigned char*>(tag));
    ok = ok && EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        return {};
    }

    out.resize(static_cast<size_t>(out_len + final_len));
    return out;
}

static std::string jstring_to_string(JNIEnv* env, jstring value) {
    if (value == nullptr) {
        return "";
    }

    const char* c = env->GetStringUTFChars(value, nullptr);
    if (c == nullptr) {
        return "";
    }

    std::string result(c);
    env->ReleaseStringUTFChars(value, c);
    return result;
}

} // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_seaboat_bytecode_ByteCodeEncryptor_encrypt(JNIEnv* env, jclass, jbyteArray input) {
    if (input == nullptr) {
        return nullptr;
    }

    jsize len = env->GetArrayLength(input);
    if (len <= 0) {
        return input;
    }

    jbyte* bytes = env->GetByteArrayElements(input, nullptr);
    if (bytes == nullptr) {
        return nullptr;
    }

    std::vector<unsigned char> in(reinterpret_cast<unsigned char*>(bytes),
                                 reinterpret_cast<unsigned char*>(bytes) + len);

    std::string class_name = "com/seaboat/bytecode/ProtectedClass";
    std::vector<unsigned char> encrypted = encrypt_buffer(in.data(), in.size(), class_name);

    env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);

    if (encrypted.empty()) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(static_cast<jsize>(encrypted.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(encrypted.size()),
                            reinterpret_cast<const jbyte*>(encrypted.data()));
    return out;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_seaboat_bytecode_ByteCodeEncryptor_decrypt(JNIEnv* env, jclass, jbyteArray input) {
    if (input == nullptr) {
        return nullptr;
    }

    jsize len = env->GetArrayLength(input);
    if (len <= 0) {
        return input;
    }

    jbyte* bytes = env->GetByteArrayElements(input, nullptr);
    if (bytes == nullptr) {
        return nullptr;
    }

    std::vector<unsigned char> in(reinterpret_cast<unsigned char*>(bytes),
                                 reinterpret_cast<unsigned char*>(bytes) + len);

    std::string class_name = "com/seaboat/bytecode/ProtectedClass";
    std::vector<unsigned char> decrypted = decrypt_buffer(in.data(), in.size(), class_name);

    env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);

    if (decrypted.empty()) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(static_cast<jsize>(decrypted.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(decrypted.size()),
                            reinterpret_cast<const jbyte*>(decrypted.data()));
    return out;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_seaboat_bytecode_ByteCodeEncryptor_encryptInternal(JNIEnv* env, jclass, jbyteArray input, jstring className) {
    if (input == nullptr) {
        return nullptr;
    }

    jsize len = env->GetArrayLength(input);
    if (len <= 0) {
        return input;
    }

    std::string class_name = jstring_to_string(env, className);
    if (class_name.empty()) {
        class_name = "com/seaboat/bytecode/ProtectedClass";
    }

    jbyte* bytes = env->GetByteArrayElements(input, nullptr);
    if (bytes == nullptr) {
        return nullptr;
    }

    std::vector<unsigned char> in(reinterpret_cast<unsigned char*>(bytes),
                                 reinterpret_cast<unsigned char*>(bytes) + len);

    std::vector<unsigned char> encrypted = encrypt_buffer(in.data(), in.size(), class_name);

    env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);

    if (encrypted.empty()) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(static_cast<jsize>(encrypted.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(encrypted.size()),
                            reinterpret_cast<const jbyte*>(encrypted.data()));
    return out;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_seaboat_bytecode_ByteCodeEncryptor_decryptInternal(JNIEnv* env, jclass, jbyteArray input, jstring className) {
    if (input == nullptr) {
        return nullptr;
    }

    jsize len = env->GetArrayLength(input);
    if (len <= 0) {
        return input;
    }

    std::string class_name = jstring_to_string(env, className);
    if (class_name.empty()) {
        class_name = "com/seaboat/bytecode/ProtectedClass";
    }

    jbyte* bytes = env->GetByteArrayElements(input, nullptr);
    if (bytes == nullptr) {
        return nullptr;
    }

    std::vector<unsigned char> in(reinterpret_cast<unsigned char*>(bytes),
                                 reinterpret_cast<unsigned char*>(bytes) + len);

    std::vector<unsigned char> decrypted = decrypt_buffer(in.data(), in.size(), class_name);

    env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);

    if (decrypted.empty()) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(static_cast<jsize>(decrypted.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(decrypted.size()),
                            reinterpret_cast<const jbyte*>(decrypted.data()));
    return out;
}

static void JNICALL ClassDecryptHook(
    jvmtiEnv* jvmti_env,
    JNIEnv* jni_env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data) {

    *new_class_data = nullptr;
    *new_class_data_len = class_data_len;

    if (class_data == nullptr || class_data_len <= 0 || name == nullptr) {
        return;
    }

    std::string class_name(name);

    if (!should_decrypt_class(name)) {
        jvmti_env->Allocate(class_data_len, new_class_data);
        if (*new_class_data != nullptr) {
            std::memcpy(*new_class_data, class_data, static_cast<size_t>(class_data_len));
        }
        return;
    }

    auto it = g_class_cache.find(class_name);
    if (it != g_class_cache.end()) {
        const auto& cached = it->second;
        jvmti_env->Allocate(static_cast<jint>(cached.size()), new_class_data);
        if (*new_class_data != nullptr) {
            std::memcpy(*new_class_data, cached.data(), cached.size());
        }
        *new_class_data_len = static_cast<jint>(cached.size());
        return;
    }

    std::vector<unsigned char> encrypted(class_data, class_data + class_data_len);
    std::vector<unsigned char> decrypted = decrypt_buffer(encrypted.data(), encrypted.size(), class_name);

    if (decrypted.empty()) {
        jvmti_env->Allocate(class_data_len, new_class_data);
        if (*new_class_data != nullptr) {
            std::memcpy(*new_class_data, class_data, static_cast<size_t>(class_data_len));
        }
        *new_class_data_len = class_data_len;
        return;
    }

    g_class_cache[class_name] = decrypted;

    jvmti_env->Allocate(static_cast<jint>(decrypted.size()), new_class_data);
    if (*new_class_data != nullptr) {
        std::memcpy(*new_class_data, decrypted.data(), decrypted.size());
    }
    *new_class_data_len = static_cast<jint>(decrypted.size());
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* vm, char* options, void* reserved) {
    jvmtiEnv* jvmti = nullptr;
    jint ret = vm->GetEnv((void**)&jvmti, JVMTI_VERSION);
    if (JNI_OK != ret) {
        std::cerr << "ERROR: Unable to access JVMTI!" << std::endl;
        return ret;
    }

    jvmtiCapabilities capabilities;
    std::memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_tag_objects = 1;
    capabilities.can_generate_object_free_events = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;
    capabilities.can_generate_vm_object_alloc_events = 1;

    jvmtiError error = jvmti->AddCapabilities(&capabilities);
    if (error != JVMTI_ERROR_NONE) {
        std::cerr << "ERROR: Unable to AddCapabilities!" << std::endl;
        return error;
    }

    jvmtiEventCallbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = &ClassDecryptHook;

    error = jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
    if (error != JVMTI_ERROR_NONE) {
        std::cerr << "ERROR: Unable to SetEventCallbacks!" << std::endl;
        return error;
    }

    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
    if (error != JVMTI_ERROR_NONE) {
        std::cerr << "ERROR: Unable to SetEventNotificationMode!" << std::endl;
        return error;
    }

    return JNI_OK;
}
