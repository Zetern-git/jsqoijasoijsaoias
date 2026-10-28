#pragma once

#include "unicode.hpp"

inline std::string jsonStr(const std::string& s) {
    std::string o = "\"";
    char buf[16];
    for (uint32_t cp : decodeUtf8(s)) {
        if (cp < 0x80) {
            switch (cp) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                case '\b': o += "\\b"; break;
                case '\f': o += "\\f"; break;
                default:
                    if (cp < 0x20) {
                        snprintf(buf, sizeof buf, "\\u%04x", cp);
                        o += buf;
                    } else {
                        o += (char)cp;
                    }
            }
        } else if (cp > 0xFFFF) {
            uint32_t v = cp - 0x10000;
            snprintf(buf, sizeof buf, "\\u%04x", 0xD800 + (v >> 10));
            o += buf;
            snprintf(buf, sizeof buf, "\\u%04x", 0xDC00 + (v & 0x3FF));
            o += buf;
        } else {
            snprintf(buf, sizeof buf, "\\u%04x", cp);
            o += buf;
        }
    }
    return o + "\"";
}

inline std::string jsonStrArr(const std::vector<std::string>& v) {
    std::string o = "[";
    for (size_t i = 0; i < v.size(); i++) {
        if (i) o += ",";
        o += jsonStr(v[i]);
    }
    return o + "]";
}

struct JV {
    enum T { Null, Bool, Int, Flt, Str, Arr, Obj } t = Null;
    long long i = 0;
    std::string s;
    std::vector<std::string> keys;
    std::vector<JV> vals;
};

inline const JV* jget(const JV& o, const std::string& k) {
    const JV* r = nullptr;
    for (size_t i = 0; i < o.keys.size(); i++)
        if (o.keys[i] == k) r = &o.vals[i];
    return r;
}

class JsonParser {
public:
    explicit JsonParser(const std::string& src) : s(src) {}
    JV parse() {
        JV v = val(0);
        ws();
        if (p != s.size()) bad();
        return v;
    }

private:
    const std::string& s;
    size_t p = 0;

    [[noreturn]] void bad() { die(kCorrupt); }

    void ws() {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r')) p++;
    }

    bool lit(const char* w) {
        size_t n = strlen(w);
        if (s.compare(p, n, w) == 0) {
            p += n;
            return true;
        }
        return false;
    }

    uint32_t hex4() {
        if (p + 4 > s.size()) bad();
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) {
            int h = hexVal(s[p + i]);
            if (h < 0) bad();
            v = v * 16 + h;
        }
        p += 4;
        return v;
    }

    std::string str() {
        p++;
        std::string o;
        for (;;) {
            if (p >= s.size()) bad();
            uint8_t c = (uint8_t)s[p++];
            if (c == '"') return o;
            if (c < 0x20) bad();
            if (c != '\\') {
                o += (char)c;
                continue;
            }
            if (p >= s.size()) bad();
            char e = s[p++];
            switch (e) {
                case '"': o += '"'; break;
                case '\\': o += '\\'; break;
                case '/': o += '/'; break;
                case 'b': o += '\b'; break;
                case 'f': o += '\f'; break;
                case 'n': o += '\n'; break;
                case 'r': o += '\r'; break;
                case 't': o += '\t'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (p + 2 > s.size() || s[p] != '\\' || s[p + 1] != 'u') bad();
                        p += 2;
                        uint32_t lo = hex4();
                        if (lo < 0xDC00 || lo > 0xDFFF) bad();
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        bad();
                    }
                    appendUtf8(o, cp);
                    break;
                }
                default: bad();
            }
        }
    }

    JV val(int depth) {
        if (depth > 200) bad();
        ws();
        if (p >= s.size()) bad();
        char c = s[p];
        JV v;
        if (c == '{') {
            v.t = JV::Obj;
            p++;
            ws();
            if (p < s.size() && s[p] == '}') {
                p++;
                return v;
            }
            for (;;) {
                ws();
                if (p >= s.size() || s[p] != '"') bad();
                std::string k = str();
                ws();
                if (p >= s.size() || s[p] != ':') bad();
                p++;
                JV x = val(depth + 1);
                v.keys.push_back(k);
                v.vals.push_back(std::move(x));
                ws();
                if (p >= s.size()) bad();
                if (s[p] == ',') {
                    p++;
                    continue;
                }
                if (s[p] == '}') {
                    p++;
                    return v;
                }
                bad();
            }
        }
        if (c == '[') {
            v.t = JV::Arr;
            p++;
            ws();
            if (p < s.size() && s[p] == ']') {
                p++;
                return v;
            }
            for (;;) {
                v.vals.push_back(val(depth + 1));
                ws();
                if (p >= s.size()) bad();
                if (s[p] == ',') {
                    p++;
                    continue;
                }
                if (s[p] == ']') {
                    p++;
                    return v;
                }
                bad();
            }
        }
        if (c == '"') {
            v.t = JV::Str;
            v.s = str();
            return v;
        }
        if (lit("true")) {
            v.t = JV::Bool;
            v.i = 1;
            return v;
        }
        if (lit("false")) {
            v.t = JV::Bool;
            return v;
        }
        if (lit("null")) return v;
        size_t st = p;
        bool isInt = true;
        if (p < s.size() && s[p] == '-') p++;
        if (p >= s.size() || !isdigit((unsigned char)s[p])) bad();
        if (s[p] == '0') {
            p++;
        } else {
            while (p < s.size() && isdigit((unsigned char)s[p])) p++;
        }
        if (p < s.size() && s[p] == '.') {
            isInt = false;
            p++;
            if (p >= s.size() || !isdigit((unsigned char)s[p])) bad();
            while (p < s.size() && isdigit((unsigned char)s[p])) p++;
        }
        if (p < s.size() && (s[p] == 'e' || s[p] == 'E')) {
            isInt = false;
            p++;
            if (p < s.size() && (s[p] == '+' || s[p] == '-')) p++;
            if (p >= s.size() || !isdigit((unsigned char)s[p])) bad();
            while (p < s.size() && isdigit((unsigned char)s[p])) p++;
        }
        std::string num = s.substr(st, p - st);
        if (isInt) {
            errno = 0;
            long long x = strtoll(num.c_str(), nullptr, 10);
            if (errno == ERANGE) {
                v.t = JV::Flt;
            } else {
                v.t = JV::Int;
                v.i = x;
            }
        } else {
            v.t = JV::Flt;
        }
        return v;
    }
};