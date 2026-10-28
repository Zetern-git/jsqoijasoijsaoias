#pragma once

#include "json.hpp"

inline const Bytes kMagic = {0xA7, 0x3C, 0x91, 0xF2, 0x08, 0xDE, 0x55, 0x1B};
inline const Bytes kMetaInfo = {0x9f, 0x1a, 'x', 'a', 'f', '-', 'M', 'E', 'T', 'A', 0x00, 0x01};
inline const Bytes kFileInfo = {0xa3, 0x7e, 'x', 'a', 'f', '-', 'F', 'I', 'L', 'E', 0x00, 0x02};
inline const Bytes kHdrAad = {0x11, 0x9C, 0x4B, 0xE7, 0x02, 0x88, 0xAF, 0x3D};

inline const uint64_t kScryptN = 1ULL << 17;
inline const uint64_t kScryptR = 8;
inline const uint64_t kScryptP = 1;
inline const uint64_t kMinBucket = 256;
inline const uint64_t kMetaBlock = 512;
inline const uint64_t kChunk = 65536;
inline const uint64_t kTag = 16;
inline const uint64_t kMaxMeta = 64ULL * 1024 * 1024;
inline const uint64_t kMaxFile = 1ULL << 40;
inline const uint64_t kMaxEntries = 1ULL << 20;
inline const long long kFormatVersion = 3;

inline Bytes hmac512(const Bytes& key, const Bytes& data) {
    Bytes out(64);
    unsigned int len = 0;
    if (!HMAC(EVP_sha512(), key.data(), (int)key.size(), data.data(), data.size(), out.data(), &len)) die("hmac failed");
    out.resize(len);
    return out;
}

inline Bytes hkdf32(const Bytes& ikm, const Bytes& info) {
    Bytes zeroSalt(64, 0);
    Bytes prk = hmac512(zeroSalt, ikm);
    Wiper<Bytes> wprk{prk};
    Bytes data = info;
    data.push_back(1);
    Bytes t = hmac512(prk, data);
    t.resize(32);
    return t;
}

inline const size_t kMinPasswordLen = 8;

inline Bytes deriveMk(const std::string& pw, const Bytes& salt) {
    if (utf8Length(pw) < kMinPasswordLen) die("password must be at least 8 characters");
    Bytes out(32);
    if (EVP_PBE_scrypt(pw.data(), pw.size(), salt.data(), salt.size(), kScryptN, kScryptR, kScryptP, 1ULL << 29, out.data(), out.size()) != 1)
        die("key derivation failed");
    return out;
}

inline Bytes subKey(const Bytes& mk, const Bytes& info) { return hkdf32(mk, info); }

struct CtxDel {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
typedef std::unique_ptr<EVP_CIPHER_CTX, CtxDel> CtxPtr;

inline Bytes aeadEncrypt(const Bytes& key, const Bytes& nonce, const uint8_t* pt, size_t n, const Bytes& aad) {
    CtxPtr c(EVP_CIPHER_CTX_new());
    if (!c) die("cipher init failed");
    Bytes out(n + kTag);
    int l = 0;
    int total = 0;
    if (EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) die("cipher init failed");
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) die("cipher init failed");
    if (EVP_EncryptInit_ex(c.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) die("cipher init failed");
    if (EVP_EncryptUpdate(c.get(), nullptr, &l, aad.data(), (int)aad.size()) != 1) die("encryption failed");
    if (EVP_EncryptUpdate(c.get(), out.data(), &l, pt, (int)n) != 1) die("encryption failed");
    total = l;
    if (EVP_EncryptFinal_ex(c.get(), out.data() + total, &l) != 1) die("encryption failed");
    total += l;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, (int)kTag, out.data() + total) != 1) die("encryption failed");
    return out;
}

inline bool aeadDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& ct, const Bytes& aad, Bytes& pt) {
    if (ct.size() < kTag) return false;
    CtxPtr c(EVP_CIPHER_CTX_new());
    if (!c) return false;
    size_t n = ct.size() - kTag;
    pt.assign(n, 0);
    int l = 0;
    if (EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) return false;
    if (EVP_DecryptUpdate(c.get(), nullptr, &l, aad.data(), (int)aad.size()) != 1) return false;
    if (n && EVP_DecryptUpdate(c.get(), pt.data(), &l, ct.data(), (int)n) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, (int)kTag, (void*)(ct.data() + n)) != 1) return false;
    int fl = 0;
    return EVP_DecryptFinal_ex(c.get(), pt.data() + n, &fl) > 0;
}

inline Bytes fileKey(const Bytes& mk, const std::string& name, const std::vector<std::string>& sec, const Bytes& salt) {
    std::string j = "[" + jsonStrArr(sec) + "," + jsonStr(name) + "]";
    Bytes info = cat(kFileInfo, Bytes(j.begin(), j.end()), Bytes{0}, salt);
    return subKey(mk, info);
}
