#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
typedef std::vector<uint8_t> Bytes;

struct Fail : std::runtime_error {
    using std::runtime_error::runtime_error;
};

[[noreturn]] inline void die(const std::string& m) { throw Fail(m); }

inline void wipe(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
}

inline void wipe(std::string& s) {
    if (s.capacity()) {
        s.resize(s.capacity());
        OPENSSL_cleanse(&s[0], s.size());
    }
    s.clear();
}

template <class C>
struct Wiper {
    C& c;
    ~Wiper() { wipe(c); }
};

struct WipedBox {
    Bytes b;
    ~WipedBox() { wipe(b); }
};

inline volatile std::sig_atomic_t gInterrupted = 0;

inline void onSignal(int) { gInterrupted = 1; }

inline void checkInterrupt() {
    if (gInterrupted) die("interrupted");
}

inline void warn(const std::string& m) { std::cerr << "warning: " << m << "\n"; }

inline const char* const kCorrupt = "archive authentication failed or data is corrupted";

inline fs::path P(const std::string& s) { return fs::path(s); }
inline std::string S(const fs::path& p) { return p.string(); }

inline void app(Bytes&) {}

template <class... R>
inline void app(Bytes& o, const Bytes& f, const R&... r) {
    o.insert(o.end(), f.begin(), f.end());
    app(o, r...);
}

template <class... A>
inline Bytes cat(const A&... a) {
    Bytes o;
    app(o, a...);
    return o;
}

inline Bytes be32(uint32_t v) {
    Bytes b(4);
    for (int i = 0; i < 4; i++) b[3 - i] = (uint8_t)(v >> (8 * i));
    return b;
}

inline Bytes be64(uint64_t v) {
    Bytes b(8);
    for (int i = 0; i < 8; i++) b[7 - i] = (uint8_t)(v >> (8 * i));
    return b;
}

inline Bytes randomBytes(size_t n) {
    Bytes b(n);
    if (n && RAND_bytes(b.data(), (int)n) != 1) die("random generator failed");
    return b;
}

inline std::string toHex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s += d[c >> 4];
        s += d[c & 15];
    }
    return s;
}

inline int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool fromHex(const std::string& s, Bytes& out) {
    if (s.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        int a = hexVal(s[i]), b = hexVal(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back((uint8_t)(a * 16 + b));
    }
    return true;
}

inline std::string b64url(const Bytes& b) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string o;
    o.reserve((b.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < b.size()) {
        uint32_t v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
        o += t[(v >> 18) & 63];
        o += t[(v >> 12) & 63];
        o += t[(v >> 6) & 63];
        o += t[v & 63];
        i += 3;
    }
    if (i + 1 == b.size()) {
        uint32_t v = b[i] << 16;
        o += t[(v >> 18) & 63];
        o += t[(v >> 12) & 63];
    } else if (i + 2 == b.size()) {
        uint32_t v = (b[i] << 16) | (b[i + 1] << 8);
        o += t[(v >> 18) & 63];
        o += t[(v >> 12) & 63];
        o += t[(v >> 6) & 63];
    }
    return o;
}

inline std::string newPassword() {
    Bytes r = randomBytes(32);
    Wiper<Bytes> wr{r};
    return b64url(r);
}

inline bool safePart(const std::string& p) {
    if (p.empty() || p == "." || p == "..") return false;
    for (char c : p) {
        if (c == '/' || c == '\\' || c == '\0') return false;
#ifdef _WIN32
        if (c == ':') return false;
#endif
    }
    return true;
}

inline void checkPart(const std::string& p) {
    if (!safePart(p)) die("unsafe path component: '" + p + "'");
}

inline std::string entryPath(const std::vector<std::string>& sec, const std::string& name) {
    std::string r;
    for (const auto& s : sec) r += s + "/";
    return r + name;
}

inline void parsePath(const std::string& s, std::vector<std::string>& sec, std::string& name) {
    std::string t = s;
    std::replace(t.begin(), t.end(), '\\', '/');
    std::vector<std::string> parts;
    std::string cur;
    for (char c : t) {
        if (c == '/') {
            if (!cur.empty()) parts.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.empty()) die("empty path");
    for (const auto& p : parts) checkPart(p);
    name = parts.back();
    sec.assign(parts.begin(), parts.end() - 1);
}

inline fs::path absPath(const std::string& s) {
    fs::path p = fs::absolute(P(s)).lexically_normal();
    if (!p.has_filename() && p.has_parent_path() && p != p.root_path()) p = p.parent_path();
    return p;
}

inline fs::path safeTarget(const fs::path& outdir, const std::vector<std::string>& sec, const std::string& name) {
    fs::path base = fs::weakly_canonical(outdir);
    fs::path t = base;
    for (const auto& p : sec) {
        checkPart(p);
        t /= P(p);
    }
    checkPart(name);
    t /= P(name);
    fs::path target = fs::weakly_canonical(t);
    auto m = std::mismatch(base.begin(), base.end(), target.begin(), target.end());
    if (m.first != base.end()) die("path escapes output dir");
    return target;
}

inline std::string splitextHead(const std::string& p) {
    size_t sep = p.rfind('/');
    size_t dot = p.rfind('.');
    if (dot != std::string::npos && (sep == std::string::npos || dot > sep)) {
        size_t fi = (sep == std::string::npos) ? 0 : sep + 1;
        while (fi < dot) {
            if (p[fi] != '.') return p.substr(0, dot);
            fi++;
        }
    }
    return p;
}

inline std::string splitextTail(const std::string& p) {
    return p.substr(splitextHead(p).size());
}