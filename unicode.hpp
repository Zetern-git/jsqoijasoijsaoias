#pragma once

#include "base.hpp"
#include "unicode_tables.hpp"

inline void appendUtf8(std::string& o, uint32_t cp) {
    if (cp < 0x80) {
        o += (char)cp;
    } else if (cp < 0x800) {
        o += (char)(0xC0 | (cp >> 6));
        o += (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        o += (char)(0xE0 | (cp >> 12));
        o += (char)(0x80 | ((cp >> 6) & 0x3F));
        o += (char)(0x80 | (cp & 0x3F));
    } else {
        o += (char)(0xF0 | (cp >> 18));
        o += (char)(0x80 | ((cp >> 12) & 0x3F));
        o += (char)(0x80 | ((cp >> 6) & 0x3F));
        o += (char)(0x80 | (cp & 0x3F));
    }
}

inline bool nextCp(const std::string& s, size_t& i, uint32_t& cp) {
    uint8_t c = (uint8_t)s[i];
    int extra;
    if (c < 0x80) {
        cp = c;
        extra = 0;
    } else if ((c & 0xE0) == 0xC0) {
        cp = c & 0x1F;
        extra = 1;
    } else if ((c & 0xF0) == 0xE0) {
        cp = c & 0x0F;
        extra = 2;
    } else if ((c & 0xF8) == 0xF0) {
        cp = c & 0x07;
        extra = 3;
    } else {
        return false;
    }
    if (i + extra >= s.size()) return false;
    for (int k = 1; k <= extra; k++) {
        uint8_t d = (uint8_t)s[i + k];
        if ((d & 0xC0) != 0x80) return false;
        cp = (cp << 6) | (d & 0x3F);
    }
    if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
        (cp >= 0xD800 && cp <= 0xDFFF))
        return false;
    i += extra + 1;
    return true;
}

inline std::vector<uint32_t> decodeUtf8(const std::string& s) {
    std::vector<uint32_t> out;
    size_t i = 0;
    while (i < s.size()) {
        uint32_t cp;
        if (!nextCp(s, i, cp)) die("invalid utf-8 in name");
        out.push_back(cp);
    }
    return out;
}

inline size_t utf8Length(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) n++;
    return n;
}

constexpr uint32_t kHangulSBase = 0xAC00;
constexpr uint32_t kHangulLBase = 0x1100;
constexpr uint32_t kHangulVBase = 0x1161;
constexpr uint32_t kHangulTBase = 0x11A7;
constexpr uint32_t kHangulLCount = 19;
constexpr uint32_t kHangulVCount = 21;
constexpr uint32_t kHangulTCount = 28;
constexpr uint32_t kHangulNCount = kHangulVCount * kHangulTCount;
constexpr uint32_t kHangulSCount = kHangulLCount * kHangulNCount;

inline uint8_t combiningClass(uint32_t cp) {
    const UniCcEntry* end = kUniCc + sizeof(kUniCc) / sizeof(kUniCc[0]);
    const UniCcEntry* it = std::lower_bound(kUniCc, end, cp, [](const UniCcEntry& e, uint32_t v) { return e.cp < v; });
    return (it != end && it->cp == cp) ? it->cc : 0;
}

inline void decomposeCp(uint32_t cp, std::vector<uint32_t>& out) {
    if (cp >= kHangulSBase && cp < kHangulSBase + kHangulSCount) {
        uint32_t s = cp - kHangulSBase;
        out.push_back(kHangulLBase + s / kHangulNCount);
        out.push_back(kHangulVBase + (s % kHangulNCount) / kHangulTCount);
        uint32_t t = s % kHangulTCount;
        if (t) out.push_back(kHangulTBase + t);
        return;
    }
    const UniDecompEntry* end = kUniDecomp + sizeof(kUniDecomp) / sizeof(kUniDecomp[0]);
    const UniDecompEntry* it = std::lower_bound(kUniDecomp, end, cp, [](const UniDecompEntry& e, uint32_t v) { return e.cp < v; });
    if (it != end && it->cp == cp) {
        for (uint32_t k = 0; k < it->len; k++) out.push_back(kUniDecompData[it->off + k]);
        return;
    }
    out.push_back(cp);
}

inline void canonicalOrder(std::vector<uint32_t>& v) {
    for (size_t i = 1; i < v.size(); i++) {
        uint8_t c = combiningClass(v[i]);
        if (!c) continue;
        for (size_t j = i; j > 0; j--) {
            uint8_t p = combiningClass(v[j - 1]);
            if (!p || p <= c) break;
            std::swap(v[j - 1], v[j]);
        }
    }
}

inline std::vector<uint32_t> nfd(const std::vector<uint32_t>& in) {
    std::vector<uint32_t> out;
    out.reserve(in.size());
    for (uint32_t cp : in) decomposeCp(cp, out);
    canonicalOrder(out);
    return out;
}

inline uint32_t simpleFold(uint32_t cp) {
    const UniFoldEntry* end = kUniFold + sizeof(kUniFold) / sizeof(kUniFold[0]);
    const UniFoldEntry* it = std::lower_bound(kUniFold, end, cp, [](const UniFoldEntry& e, uint32_t v) { return e.cp < v; });
    return (it != end && it->cp == cp) ? it->to : cp;
}

inline void fullFoldCp(uint32_t cp, std::vector<uint32_t>& out) {
    const UniFullFoldEntry* end = kUniFullFold + sizeof(kUniFullFold) / sizeof(kUniFullFold[0]);
    const UniFullFoldEntry* it = std::lower_bound(kUniFullFold, end, cp, [](const UniFullFoldEntry& e, uint32_t v) { return e.cp < v; });
    if (it != end && it->cp == cp) {
        for (uint32_t k = 0; k < it->len; k++) out.push_back(kUniFullFoldData[it->off + k]);
        return;
    }
    out.push_back(simpleFold(cp));
}

inline std::string foldRun(const std::vector<uint32_t>& cps) {
    std::vector<uint32_t> v = nfd(cps);
    std::vector<uint32_t> folded;
    folded.reserve(v.size());
    for (uint32_t c : v) fullFoldCp(c, folded);
    v = nfd(folded);
    std::string o;
    for (uint32_t c : v) appendUtf8(o, c);
    return o;
}

inline std::string foldKey(const std::string& s) {
    std::string out;
    std::vector<uint32_t> run;
    size_t i = 0;
    while (i < s.size()) {
        size_t start = i;
        uint32_t cp;
        if (nextCp(s, i, cp)) {
            run.push_back(cp);
            continue;
        }
        out += foldRun(run);
        run.clear();
        i = start + 1;
        out += s[start];
    }
    out += foldRun(run);
    return out;
}
