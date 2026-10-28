#pragma once

#include "crypto.hpp"

inline uint64_t bucketOf(uint64_t n, uint64_t base = kMinBucket) {
    if (n <= base) return base;
    uint64_t b = base;
    while (b < n) b <<= 1;
    return b;
}

inline uint64_t ctLen(uint64_t padded) {
    if (padded <= kChunk) return padded + kTag;
    return padded + kTag * (padded / kChunk);
}

inline void chunkPlan(uint64_t padded, uint64_t& n, uint64_t& sz) {
    if (padded <= kChunk) {
        n = 1;
        sz = padded;
        return;
    }
    n = padded / kChunk;
    sz = kChunk;
}

inline Bytes padMeta(const Bytes& data) {
    uint64_t n = data.size() + 4;
    uint64_t minTarget = std::max<uint64_t>(n + kTag, kMetaBlock);
    uint64_t target = bucketOf(minTarget, kMetaBlock);
    uint64_t paddedPt = target - kTag;
    return cat(be32((uint32_t)data.size()), data, randomBytes(paddedPt - n));
}

class Source {
public:
    virtual ~Source() {}
    virtual size_t read(uint8_t* buf, size_t n) = 0;
};

typedef std::function<std::unique_ptr<Source>()> Factory;

struct Entry {
    std::string name;
    std::vector<std::string> sec;
    uint64_t size;
    Factory make;
};

struct FMeta {
    std::string name;
    std::vector<std::string> sec;
    uint64_t size = 0;
    uint64_t off = 0;
    uint64_t len = 0;
    std::string prefix;
};

inline size_t readFull(Source& s, uint8_t* b, size_t n) {
    size_t g = 0;
    while (g < n) {
        size_t r = s.read(b + g, n - g);
        if (!r) break;
        g += r;
    }
    return g;
}

class FileSource : public Source {
public:
    explicit FileSource(const std::string& path) : f(P(path), std::ios::binary) {
        if (!f) die("cannot open file: " + path);
    }
    size_t read(uint8_t* buf, size_t n) override {
        f.read((char*)buf, (std::streamsize)n);
        return (size_t)f.gcount();
    }

private:
    std::ifstream f;
};

class zcfSource : public Source {
public:
    zcfSource(const std::string& path, uint64_t blobStart, const Bytes& salt_, const Bytes& mk, const FMeta& e) : salt(salt_) {
        key = fileKey(mk, e.name, e.sec, salt);
        if (!fromHex(e.prefix, prefix)) die(kCorrupt);
        realRemaining = e.size;
        chunkPlan(bucketOf(e.size), n, sz);
        f.open(P(path), std::ios::binary);
        if (!f) die("cannot open zcf file");
        f.seekg((std::streamoff)(blobStart + e.off));
    }

    ~zcfSource() {
        wipe(key);
        wipe(cur);
    }

    size_t read(uint8_t* buf, size_t want) override {
        while (pos >= cur.size()) {
            if (idx >= n) return 0;
            size_t encLen = (size_t)(sz + kTag);
            Bytes enc(encLen);
            f.read((char*)enc.data(), (std::streamsize)encLen);
            if ((size_t)f.gcount() != encLen) die(kCorrupt);
            Bytes idxb = be64(idx);
            Bytes nonce = cat(prefix, idxb);
            Bytes aad = cat(kHdrAad, salt, prefix, idxb);
            Bytes pt;
            Wiper<Bytes> wpt{pt};
            if (!aeadDecrypt(key, nonce, enc, aad, pt)) die(kCorrupt);
            idx++;
            uint64_t take = std::min<uint64_t>(pt.size(), realRemaining);
            realRemaining -= take;
            cur.assign(pt.begin(), pt.begin() + (size_t)take);
            pos = 0;
        }
        size_t k = std::min(want, cur.size() - pos);
        memcpy(buf, cur.data() + pos, k);
        pos += k;
        return k;
    }

private:
    std::ifstream f;
    Bytes key, prefix, salt, cur;
    uint64_t realRemaining = 0, n = 0, sz = 0, idx = 0;
    size_t pos = 0;
};

struct Header {
    Bytes salt, mk;
    std::vector<FMeta> files;
    uint64_t blobStart = 0;
    ~Header() { wipe(mk); }
};

template <class E>
inline void checkFoldedNames(const std::vector<E>& list, const std::string& msg) {
    std::map<std::string, std::string> files;
    std::map<std::string, std::string> dirs;
    for (const auto& e : list) {
        std::string ep = entryPath(e.sec, e.name);
        std::string fp = foldKey(ep);
        if (files.count(fp) || dirs.count(fp)) die(msg + ep);
        files[fp] = ep;
        std::string d;
        for (size_t k = 0; k < e.sec.size(); k++) {
            if (k) d += "/";
            d += e.sec[k];
            std::string fd = foldKey(d);
            if (files.count(fd)) die(msg + d);
            auto it = dirs.find(fd);
            if (it == dirs.end()) dirs.emplace(fd, d);
            else if (it->second != d) die(msg + d);
        }
    }
}

inline Header readHeaderAndMeta(const std::string& path, const std::string& pw) {
    std::error_code ec;
    uint64_t total = fs::file_size(P(path), ec);
    if (ec) die("cannot stat zcf file");
    std::ifstream f(P(path), std::ios::binary);
    if (!f) die("cannot stat zcf file");
    auto rd = [&](size_t n) {
        Bytes b(n);
        f.read((char*)b.data(), (std::streamsize)n);
        b.resize((size_t)f.gcount());
        return b;
    };
    Bytes magic = rd(8);
    if (magic.size() != 8 || magic != kMagic) die("invalid zcf file");
    Bytes salt = rd(32);
    if (salt.size() != 32) die("invalid zcf file");
    Bytes mlb = rd(4);
    if (mlb.size() != 4) die("invalid zcf file");
    uint64_t ml = ((uint64_t)mlb[0] << 24) | ((uint64_t)mlb[1] << 16) | ((uint64_t)mlb[2] << 8) | mlb[3];
    if (ml > kMaxMeta || total < 56 || ml > total - 56) die("invalid zcf file");
    Bytes mn = rd(12);
    if (mn.size() != 12) die("invalid zcf file");
    Bytes mct = rd((size_t)ml);
    if (mct.size() != ml) die("invalid zcf file");
    uint64_t blobStart = 56 + ml;
    f.close();

    Bytes mk = deriveMk(pw, salt);
    Wiper<Bytes> wmk{mk};
    Bytes fmk = subKey(mk, kMetaInfo);
    Wiper<Bytes> wfmk{fmk};
    Bytes mp;
    Wiper<Bytes> wmp{mp};
    if (!aeadDecrypt(fmk, mn, mct, cat(kHdrAad, kMagic, salt), mp)) die(kCorrupt);
    if (mp.size() < 4) die(kCorrupt);
    uint64_t plen = ((uint64_t)mp[0] << 24) | ((uint64_t)mp[1] << 16) | ((uint64_t)mp[2] << 8) | mp[3];
    if (plen > mp.size() - 4) die(kCorrupt);
    std::string js((const char*)mp.data() + 4, (size_t)plen);
    Wiper<std::string> wjs{js};
    JV root = JsonParser(js).parse();
    const JV* ver = root.t == JV::Obj ? jget(root, "v") : nullptr;
    if (!ver || ver->t != JV::Int) die(kCorrupt);
    if (ver->i != kFormatVersion) die("unsupported zcf format version: " + std::to_string(ver->i));
    const JV* files = root.t == JV::Obj ? jget(root, "files") : nullptr;
    if (!files || files->t != JV::Arr) die(kCorrupt);
    if (files->vals.size() > kMaxEntries) die("too many entries");

    Header h;
    h.salt = salt;
    h.mk = mk;
    h.blobStart = blobStart;
    for (const JV& e : files->vals) {
        if (e.t != JV::Obj) die(kCorrupt);
        const JV* name = jget(e, "n");
        const JV* sec = jget(e, "sec");
        const JV* size = jget(e, "s");
        const JV* off = jget(e, "o");
        const JV* ln = jget(e, "l");
        const JV* pr = jget(e, "p");
        if (!name || name->t != JV::Str || name->s.empty()) die(kCorrupt);
        if (sec && sec->t != JV::Arr) die(kCorrupt);
        FMeta m;
        m.name = name->s;
        if (sec) {
            for (const JV& x : sec->vals) {
                if (x.t != JV::Str || x.s.empty()) die(kCorrupt);
                m.sec.push_back(x.s);
            }
        }
        if (!size || !off || !ln || size->t != JV::Int || off->t != JV::Int || ln->t != JV::Int) die(kCorrupt);
        if (size->i < 0 || (uint64_t)size->i > kMaxFile || off->i < 0 || ln->i < 0) die(kCorrupt);
        if (!pr || pr->t != JV::Str) die(kCorrupt);
        Bytes pb;
        if (!fromHex(pr->s, pb) || pb.size() != 4) die(kCorrupt);
        m.size = (uint64_t)size->i;
        m.off = (uint64_t)off->i;
        m.len = (uint64_t)ln->i;
        m.prefix = pr->s;
        if (m.len != ctLen(bucketOf(m.size))) die(kCorrupt);
        h.files.push_back(m);
    }
    uint64_t blobSize = total - blobStart;
    std::vector<size_t> order(h.files.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = i;
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return h.files[a].off < h.files[b].off; });
    uint64_t lastEnd = 0;
    for (size_t i : order) {
        if (h.files[i].off < lastEnd) die(kCorrupt);
        lastEnd = h.files[i].off + h.files[i].len;
    }
    for (size_t i : order) {
        if (h.files[i].off > blobSize || h.files[i].len > blobSize - h.files[i].off) die(kCorrupt);
    }
    checkFoldedNames(h.files, "archive entries collide ignoring case: ");
    return h;
}

inline void validateEntries(const std::vector<Entry>& entries) {
    if (entries.size() > kMaxEntries) die("too many entries");
    if ((uint64_t)entries.size() > (1ULL << 32)) die("too many entries for prefix space");
    std::set<std::string> paths, dirs;
    for (const auto& e : entries) {
        checkPart(e.name);
        for (const auto& p : e.sec) checkPart(p);
        std::string ep = entryPath(e.sec, e.name);
        if (paths.count(ep)) die("duplicate entry: " + ep);
        paths.insert(ep);
        std::string d;
        for (size_t k = 0; k < e.sec.size(); k++) {
            if (k) d += "/";
            d += e.sec[k];
            dirs.insert(d);
        }
    }
    checkFoldedNames(entries, "entries collide ignoring case: ");
    for (const auto& p : paths) {
        if (dirs.count(p)) die("file/dir conflict: " + p);
    }
}

inline bool createNewPrivate(const fs::path& p) {
#ifdef _WIN32
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_EXISTS) return false;
        die("cannot create: " + S(p));
    }
    CloseHandle(h);
#else
    int fd = ::open(p.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        if (errno == EEXIST) return false;
        die("cannot create: " + S(p));
    }
    ::close(fd);
#endif
    return true;
}

inline bool createNewPrivateDir(const fs::path& p) {
#ifdef _WIN32
    if (!CreateDirectoryW(p.c_str(), nullptr)) {
        if (GetLastError() == ERROR_ALREADY_EXISTS) return false;
        die("cannot create: " + S(p));
    }
#else
    if (::mkdir(p.c_str(), 0700) != 0) {
        if (errno == EEXIST) return false;
        die("cannot create: " + S(p));
    }
#endif
    return true;
}

inline fs::path randomName(const fs::path& dir, const std::string& prefix) {
    return dir / P(prefix + toHex(randomBytes(6)));
}

inline void syncPath(const fs::path& p) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesW(p.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) die("cannot sync: " + S(p));
    bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    DWORD flags = FILE_FLAG_WRITE_THROUGH;
    if (isDir) flags |= FILE_FLAG_BACKUP_SEMANTICS;
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, flags, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (isDir) return;
        die("cannot sync: " + S(p));
    }
    BOOL ok = FlushFileBuffers(h);
    DWORD err = GetLastError();
    CloseHandle(h);
    if (!ok && !(isDir && err == ERROR_ACCESS_DENIED)) die("FlushFileBuffers failed: " + S(p));
#else
    int fd = ::open(p.c_str(), O_RDONLY);
    if (fd < 0) die("cannot sync: " + S(p));
    int r;
#ifdef F_FULLFSYNC
    r = ::fcntl(fd, F_FULLFSYNC);
    if (r != 0) r = ::fsync(fd);
#else
    r = ::fsync(fd);
#endif
    ::close(fd);
    if (r != 0) die("fsync failed: " + S(p));
#endif
}

inline void writeFileStream(std::ofstream& out, const Bytes& key, const Bytes& salt, const Bytes& prefix, Source& src, uint64_t realSize) {
    uint64_t padded = bucketOf(realSize);
    uint64_t n, sz;
    chunkPlan(padded, n, sz);
    uint64_t remaining = realSize;
    Bytes buf((size_t)sz);
    Wiper<Bytes> wbuf{buf};
    for (uint64_t idx = 0; idx < n; idx++) {
        checkInterrupt();
        size_t want = (size_t)std::min<uint64_t>(sz, remaining);
        if (readFull(src, buf.data(), want) != want) die("file shrank while packing");
        remaining -= want;
        if (want < sz && RAND_bytes(buf.data() + want, (int)(sz - want)) != 1) die("random generator failed");
        Bytes idxb = be64(idx);
        Bytes nonce = cat(prefix, idxb);
        Bytes aad = cat(kHdrAad, salt, prefix, idxb);
        Bytes ct = aeadEncrypt(key, nonce, buf.data(), (size_t)sz, aad);
        out.write((const char*)ct.data(), (std::streamsize)ct.size());
        if (!out) die("write failed");
    }
    uint8_t extra;
    if (src.read(&extra, 1) != 0) die("file grew while packing");
}

inline void writezcf(const std::string& path, const std::string& pw, std::vector<Entry>& entries) {
    validateEntries(entries);
    Bytes salt = randomBytes(32);
    Bytes mk = deriveMk(pw, salt);
    Wiper<Bytes> wmk{mk};
    Bytes fmk = subKey(mk, kMetaInfo);
    Wiper<Bytes> wfmk{fmk};
    std::vector<FMeta> metas;
    uint64_t offset = 0;
    for (size_t i = 0; i < entries.size(); i++) {
        const Entry& e = entries[i];
        if (e.size > kMaxFile) die("invalid size for: " + e.name);
        FMeta m;
        m.name = e.name;
        m.sec = e.sec;
        m.size = e.size;
        m.prefix = toHex(be32((uint32_t)i));
        m.off = offset;
        m.len = ctLen(bucketOf(e.size));
        offset += m.len;
        metas.push_back(m);
    }
    std::string mj = "{\"v\":" + std::to_string(kFormatVersion) + ",\"files\":[";
    for (size_t i = 0; i < metas.size(); i++) {
        const FMeta& m = metas[i];
        if (i) mj += ",";
        mj += "{\"n\":" + jsonStr(m.name) + ",\"sec\":" + jsonStrArr(m.sec) + ",\"s\":" + std::to_string(m.size) + ",\"p\":\"" + m.prefix +
              "\",\"o\":" + std::to_string(m.off) + ",\"l\":" + std::to_string(m.len) + "}";
    }
    mj += "]}";
    Bytes mp = padMeta(Bytes(mj.begin(), mj.end()));
    Wiper<Bytes> wmp{mp};
    Wiper<std::string> wmj{mj};
    Bytes mn = randomBytes(12);
    Bytes mct = aeadEncrypt(fmk, mn, mp.data(), mp.size(), cat(kHdrAad, kMagic, salt));

    fs::path d = absPath(path).parent_path();
    if (d.empty()) d = ".";
    fs::path tmp;
    for (;;) {
        tmp = randomName(d, ".zcf_tmp_");
        if (createNewPrivate(tmp)) break;
    }
    try {
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) die("cannot write: " + S(tmp));
            auto w = [&](const Bytes& b) { out.write((const char*)b.data(), (std::streamsize)b.size()); };
            w(kMagic);
            w(salt);
            w(be32((uint32_t)mct.size()));
            w(mn);
            w(mct);
            for (size_t i = 0; i < entries.size(); i++) {
                Bytes key = fileKey(mk, entries[i].name, entries[i].sec, salt);
                Wiper<Bytes> wkey{key};
                Bytes prefix;
                fromHex(metas[i].prefix, prefix);
                std::unique_ptr<Source> src = entries[i].make();
                writeFileStream(out, key, salt, prefix, *src, entries[i].size);
            }
            out.flush();
            if (!out) die("write failed");
            out.close();
            if (out.fail()) die("write failed");
        }
        syncPath(tmp);
        fs::rename(tmp, P(path));
        syncPath(d);
    } catch (...) {
        std::error_code rec;
        fs::remove(tmp, rec);
        throw;
    }
}

inline std::vector<Entry> existingEntries(const std::string& zcf, const Header& h) {
    std::vector<Entry> out;
    std::shared_ptr<WipedBox> salt(new WipedBox);
    salt->b = h.salt;
    std::shared_ptr<WipedBox> mk(new WipedBox);
    mk->b = h.mk;
    uint64_t bs = h.blobStart;
    for (const FMeta& e : h.files) {
        FMeta em = e;
        out.push_back({e.name, e.sec, e.size, [zcf, bs, salt, mk, em]() { return std::unique_ptr<Source>(new zcfSource(zcf, bs, salt->b, mk->b, em)); }});
    }
    return out;
}

typedef std::function<void(const std::vector<std::string>&, const std::string&, const std::string&)> WalkCb;

inline void walkSections(const std::string& root, const WalkCb& cb) {
    fs::path rootAbs = absPath(root);
    fs::path baseParent = rootAbs.parent_path();
    std::function<void(const fs::path&)> rec = [&](const fs::path& dir) {
        fs::path rel = dir.lexically_relative(baseParent);
        std::vector<std::string> parts;
        if (rel != "." && !rel.empty()) {
            for (const auto& c : rel) {
                std::string s = S(c);
                if (s.empty() || s == ".") continue;
                parts.push_back(s);
            }
        }
        for (const auto& p : parts) checkPart(p);
        std::vector<fs::directory_entry> ents;
        for (const auto& e : fs::directory_iterator(dir)) ents.push_back(e);
        std::sort(ents.begin(), ents.end(), [](const fs::directory_entry& a, const fs::directory_entry& b) { return S(a.path().filename()) < S(b.path().filename()); });
        std::vector<fs::path> dirs;
        for (const auto& e : ents) {
            std::error_code ec;
            fs::file_status st = e.symlink_status(ec);
            if (fs::is_symlink(st)) {
                warn("skipping symlink: " + S(e.path()));
                continue;
            }
            std::string fn = S(e.path().filename());
            if (fs::is_directory(st)) {
                if (!safePart(fn)) {
                    warn("skipping directory with unsafe name: " + S(e.path()));
                    continue;
                }
                dirs.push_back(e.path());
                continue;
            }
            if (!fs::is_regular_file(st)) {
                warn("skipping non-regular file: " + S(e.path()));
                continue;
            }
            cb(parts, fn, S(e.path()));
        }
        for (const auto& d : dirs) rec(d);
    };
    rec(rootAbs);
}

inline Factory fileFactory(const std::string& p) {
    return [p]() { return std::unique_ptr<Source>(new FileSource(p)); };
}

enum class OnExisting { Fail, Skip, Replace };

struct Collected {
    std::vector<Entry> entries;
    std::vector<std::string> added, skipped, replaced;
};

inline bool isTarget(const fs::path& p, const fs::path& zcf, const fs::path& zcfCanon) {
    std::error_code ec;
    if (fs::exists(zcf, ec) && fs::exists(p, ec) && fs::equivalent(p, zcf, ec) && !ec) return true;
    return fs::weakly_canonical(p) == zcfCanon;
}

inline bool portableName(const std::string& n, std::string& why) {
    if (n.empty()) {
        why = "empty name";
        return false;
    }
    try {
        decodeUtf8(n);
    } catch (const Fail&) {
        why = "name is not valid UTF-8";
        return false;
    }
    if (n.back() == '.' || n.back() == ' ') {
        why = "name ends with a dot or a space";
        return false;
    }
    const std::string forbidden = "<>:\"|?*";
    for (char c : n) {
        if ((unsigned char)c < 0x20 || forbidden.find(c) != std::string::npos) {
            why = "name contains a character not allowed on Windows";
            return false;
        }
    }
    std::string stem = n.substr(0, n.find('.'));
    for (auto& c : stem) c = (char)std::toupper((unsigned char)c);
    static const std::set<std::string> reserved = [] {
        std::set<std::string> r = {"CON", "PRN", "AUX", "NUL"};
        for (int i = 0; i <= 9; i++) {
            r.insert("COM" + std::to_string(i));
            r.insert("LPT" + std::to_string(i));
        }
        return r;
    }();
    if (reserved.count(stem)) {
        why = "name is reserved on Windows";
        return false;
    }
    return true;
}

inline bool namesPortable(const std::vector<std::string>& sec, const std::string& name, std::string& why) {
    for (const auto& p : sec)
        if (!safePart(p)) {
            why = "unsafe path component";
            return false;
        }
    if (!safePart(name)) {
        why = "unsafe path component";
        return false;
    }
    for (const auto& p : sec)
        if (!portableName(p, why)) return false;
    return portableName(name, why);
}

inline Collected collectInputs(const std::vector<std::string>& inputs, const std::vector<Entry>& base, const std::string& zcf, OnExisting policy) {
    Collected c;
    c.entries = base;
    fs::path zcfPath = P(zcf);
    fs::path zcfCanon = fs::weakly_canonical(zcfPath);
    std::set<std::string> existing, folded, fresh;
    for (const auto& e : base) {
        std::string p = entryPath(e.sec, e.name);
        existing.insert(p);
        folded.insert(foldKey(p));
    }
    auto add = [&](const std::vector<std::string>& sec, const std::string& name, const fs::path& src) {
        std::string p = entryPath(sec, name);
        std::string why;
        if (!namesPortable(sec, name, why)) {
            warn("skipping " + p + ": " + why);
            return;
        }
        if (policy != OnExisting::Skip && fresh.count(p)) die("duplicate input: " + p);
        if (existing.count(p)) {
            if (policy == OnExisting::Skip) {
                c.skipped.push_back(p);
                return;
            }
            if (policy == OnExisting::Fail) die("entry already exists: " + p + " (use --skip-existing or --overwrite)");
            c.entries.erase(std::remove_if(c.entries.begin(), c.entries.end(), [&](const Entry& e) { return entryPath(e.sec, e.name) == p; }), c.entries.end());
            c.replaced.push_back(p);
        } else {
            if (folded.count(foldKey(p))) {
                warn("skipping " + p + ": name collides with another entry ignoring case");
                return;
            }
            c.added.push_back(p);
        }
        c.entries.push_back({name, sec, (uint64_t)fs::file_size(src), fileFactory(S(src))});
        existing.insert(p);
        folded.insert(foldKey(p));
        fresh.insert(p);
    };
    for (const auto& it : inputs) {
        std::error_code ec;
        fs::file_status st = fs::symlink_status(P(it), ec);
        if (fs::is_symlink(st)) {
            warn("skipping symlink: " + it);
            continue;
        }
        if (fs::is_directory(st)) {
            walkSections(it, [&](const std::vector<std::string>& sec, const std::string& name, const std::string& fp) {
                if (isTarget(P(fp), zcfPath, zcfCanon)) return;
                add(sec, name, P(fp));
            });
        } else if (fs::is_regular_file(st)) {
            if (isTarget(P(it), zcfPath, zcfCanon)) die("cannot add target .zcf into itself");
            add({}, S(P(it).filename()), P(it));
        } else {
            die("no such file or directory: " + it);
        }
    }
    return c;
}