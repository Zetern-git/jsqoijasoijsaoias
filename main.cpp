#include "storage.hpp"

static void reservePasswordFile(const std::string& archive, const std::string& savePath) {
    if (savePath.empty()) return;
    if (absPath(savePath) == absPath(archive)) die("password file must not be the archive itself");
    if (!createNewPrivate(P(savePath))) die("password file already exists: " + savePath);
}

static void emitPassword(const std::string& pw, const std::string& savePath) {
    if (savePath.empty()) {
        std::cerr << "PASSWORD (shown once, save it): " << pw << "\n";
        return;
    }
    {
        std::ofstream f(P(savePath), std::ios::binary | std::ios::trunc);
        if (!f) die("cannot write: " + savePath);
        f << pw << "\n";
        f.close();
        if (f.fail()) die("write failed: " + savePath);
    }
    std::cerr << "password saved to: " << savePath << "\n";
}

static void createArchive(const std::string& path, const std::string& savePw, std::vector<Entry>& entries) {
    reservePasswordFile(path, savePw);
    std::string pw = newPassword();
    Wiper<std::string> wpw{pw};
    try {
        writezcf(path, pw, entries);
    } catch (...) {
        std::error_code rec;
        if (!savePw.empty()) fs::remove(P(savePw), rec);
        throw;
    }
    try {
        emitPassword(pw, savePw);
    } catch (...) {
        std::error_code rec;
        fs::remove(P(path), rec);
        if (!savePw.empty()) fs::remove(P(savePw), rec);
        throw;
    }
}

struct Opts {
    std::vector<std::string> items;
    std::string pw;
    std::string savePw;
    bool force = false;
    bool skipExisting = false;
    bool overwrite = false;
    ~Opts() { wipe(pw); }
};

static OnExisting policyOf(const Opts& o) {
    if (o.overwrite) return OnExisting::Replace;
    if (o.skipExisting) return OnExisting::Skip;
    return OnExisting::Fail;
}

static bool stdinIsTty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

#ifndef _WIN32
static termios gSavedTerm;

static void onPromptSignal(int sig) {
    tcsetattr(STDIN_FILENO, TCSANOW, &gSavedTerm);
    _exit(128 + sig);
}
#endif

static constexpr size_t kMaxPasswordBytes = 1024;

static bool readStdinByte(char& c) {
    for (;;) {
#ifdef _WIN32
        int r = _read(0, &c, 1);
#else
        ssize_t r = ::read(STDIN_FILENO, &c, 1);
#endif
        if (r == 1) return true;
        if (r == 0) return false;
#ifndef _WIN32
        if (errno == EINTR) {
            checkInterrupt();
            continue;
        }
#endif
        return false;
    }
}

static void readStdinLine(std::string& s) {
    wipe(s);
    s.reserve(kMaxPasswordBytes);
    char c = 0;
    while (readStdinByte(c) && c != '\n') {
        if (s.size() >= kMaxPasswordBytes) die("password is too long");
        s.push_back(c);
    }
    if (!s.empty() && s.back() == '\r') s.pop_back();
}

static void readLineNoEcho(std::string& s) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool restore = GetConsoleMode(h, &mode) != 0;
    if (restore) SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    readStdinLine(s);
    if (restore) SetConsoleMode(h, mode);
#else
    termios oldt{};
    bool restore = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (restore) {
        gSavedTerm = oldt;
        termios quiet = oldt;
        quiet.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
        std::signal(SIGINT, onPromptSignal);
        std::signal(SIGTERM, onPromptSignal);
    }
    readStdinLine(s);
    if (restore) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::signal(SIGINT, onSignal);
        std::signal(SIGTERM, onSignal);
    }
#endif
    std::cerr << "\n";
}

static void obtainPassword(std::string& pw) {
    if (stdinIsTty()) {
        std::cerr << "Password: " << std::flush;
        readLineNoEcho(pw);
    } else {
        readStdinLine(pw);
    }
    if (pw.empty()) die("no password provided: pipe it on stdin or enter it at the prompt");
}

static void splitOpts(Opts& o, const std::vector<std::string>& args, bool needPw = true) {
    size_t i = 0;
    while (i < args.size()) {
        const std::string& a = args[i];
        if (a == "--PASSWORD" || a.compare(0, 11, "--PASSWORD=") == 0) {
            die("passwords are not accepted on the command line; pipe the password on stdin or enter it at the prompt");
        } else if (a == "--save-password") {
            if (i + 1 >= args.size()) die("--save-password requires a path");
            o.savePw = args[i + 1];
            i += 2;
        } else if (a == "--force") {
            o.force = true;
            i += 1;
        } else if (a == "--skip-existing") {
            o.skipExisting = true;
            i += 1;
        } else if (a == "--overwrite") {
            o.overwrite = true;
            i += 1;
        } else {
            o.items.push_back(a);
            i += 1;
        }
    }
    if (o.skipExisting && o.overwrite) die("--skip-existing and --overwrite cannot be used together");
    if (!needPw && (o.skipExisting || o.overwrite)) die("--skip-existing and --overwrite are only valid with -af and -aaf");
    if (needPw && !o.savePw.empty()) die("--save-password is only valid with -c and -caaf");
    if (needPw) obtainPassword(o.pw);
}

static void splitzcfAndInputs(const std::vector<std::string>& items, std::string& zcf, std::vector<std::string>& rest) {
    if (items.empty() || items[0].compare(0, 2, "--") == 0) die("archive path must be the first argument");
    zcf = items[0];
    rest.assign(items.begin() + 1, items.end());
}

static void cmdCreate(const std::string& path, bool force, const std::string& savePw) {
    std::error_code ec;
    if (fs::exists(P(path), ec) && !force) die("target exists, use --force to overwrite: " + path);
    std::vector<Entry> none;
    createArchive(path, savePw, none);
    std::cout << "zcf created: " << path << "\n";
}

static void cmdCaaf(const std::string& path, const std::vector<std::string>& inputs, bool force, const std::string& savePw) {
    if (inputs.empty()) die("no inputs");
    std::error_code ec;
    if (fs::exists(P(path), ec) && !force) die("target exists, use --force to overwrite: " + path);
    Collected c = collectInputs(inputs, {}, path, OnExisting::Fail);
    createArchive(path, savePw, c.entries);
    std::cout << "zcf created: " << path << " | entries: " << c.entries.size() << "\n";
}

static void cmdAf(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> inputs;
    splitzcfAndInputs(o.items, zcf, inputs);
    if (inputs.empty()) die("no inputs");
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::vector<Entry> base = existingEntries(zcf, h);
    Collected c = collectInputs(inputs, base, zcf, policyOf(o));
    writezcf(zcf, o.pw, c.entries);
    std::cout << "Added: " << c.added.size() << " entries";
    if (!c.replaced.empty()) std::cout << ", replaced: " << c.replaced.size();
    if (!c.skipped.empty()) std::cout << ", skipped: " << c.skipped.size();
    std::cout << "\n";
}

static bool fnmatchPy(const std::string& pat, const std::string& s) {
    size_t pi = 0, si = 0, starP = std::string::npos, starS = 0;
    while (si < s.size()) {
        bool ok = false;
        size_t np = pi;
        unsigned char sc = (unsigned char)s[si];
        if (pi < pat.size()) {
            char c = pat[pi];
            if (c == '*') {
                starP = pi++;
                starS = si;
                continue;
            }
            if (c == '?') {
                ok = true;
                np = pi + 1;
            } else if (c == '[') {
                size_t j = pi + 1;
                if (j < pat.size() && pat[j] == '!') j++;
                if (j < pat.size() && pat[j] == ']') j++;
                while (j < pat.size() && pat[j] != ']') j++;
                if (j >= pat.size()) {
                    ok = (s[si] == '[');
                    np = pi + 1;
                } else {
                    std::string st = pat.substr(pi + 1, j - pi - 1);
                    bool neg = false;
                    if (!st.empty() && st[0] == '!') {
                        neg = true;
                        st.erase(0, 1);
                    }
                    bool m = false;
                    for (size_t k = 0; k < st.size();) {
                        if (k + 2 < st.size() && st[k + 1] == '-') {
                            if ((unsigned char)st[k] <= sc && sc <= (unsigned char)st[k + 2]) m = true;
                            k += 3;
                        } else {
                            if ((unsigned char)st[k] == sc) m = true;
                            k++;
                        }
                    }
                    ok = (m != neg);
                    np = j + 1;
                }
            } else {
                ok = ((unsigned char)c == sc);
                np = pi + 1;
            }
        }
        if (ok) {
            pi = np;
            si++;
        } else if (starP != std::string::npos) {
            pi = starP + 1;
            si = ++starS;
        } else {
            return false;
        }
    }
    while (pi < pat.size() && pat[pi] == '*') pi++;
    return pi == pat.size();
}

static void cmdAaf(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> exclusions;
    splitzcfAndInputs(o.items, zcf, exclusions);
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::vector<Entry> base = existingEntries(zcf, h);
    fs::path zcfPath = P(zcf);
    fs::path zcfCanon = fs::weakly_canonical(zcfPath);
    std::vector<std::string> names;
    for (const auto& e : fs::directory_iterator(".")) names.push_back(S(e.path().filename()));
    std::sort(names.begin(), names.end());
    std::vector<std::string> files;
    for (const auto& name : names) {
        if (isTarget(P(name), zcfPath, zcfCanon)) continue;
        std::error_code ec;
        fs::file_status st = fs::symlink_status(P(name), ec);
        if (fs::is_symlink(st)) {
            warn("skipping symlink: " + name);
            continue;
        }
        if (!fs::is_regular_file(st)) continue;
        bool excluded = false;
        for (const auto& pat : exclusions)
            if (fnmatchPy(pat, name)) excluded = true;
        if (!excluded) files.push_back(name);
    }
    Collected c = collectInputs(files, base, zcf, policyOf(o));
    writezcf(zcf, o.pw, c.entries);
    std::cout << "Added: " << c.added.size() << " files";
    if (!c.replaced.empty()) std::cout << ", replaced: " << c.replaced.size();
    if (!c.skipped.empty()) std::cout << ", skipped: " << c.skipped.size();
    std::cout << "\n";
}

static void cmdUnpack(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> extra;
    splitzcfAndInputs(o.items, zcf, extra);
    if (!extra.empty()) die("unexpected arguments");
    Header h = readHeaderAndMeta(zcf, o.pw);
    for (const FMeta& e : h.files) {
        std::string why;
        if (!namesPortable(e.sec, e.name, why)) die("archive entry is not portable: " + entryPath(e.sec, e.name) + ": " + why);
    }
    std::string baseName = S(P(zcf).filename());
    fs::path targetDir = absPath(splitextHead(baseName) + "_extracted");
    fs::path parent = targetDir.parent_path();
    if (parent.empty()) parent = ".";
    fs::create_directories(parent);
    fs::path tmpDir;
    for (;;) {
        tmpDir = randomName(parent, ".zcf_extract_");
        if (createNewPrivateDir(tmpDir)) break;
    }
    std::string finalName;
    try {
        for (const FMeta& e : h.files) {
            checkInterrupt();
            fs::path target = safeTarget(tmpDir, e.sec, e.name);
            fs::create_directories(target.parent_path());
            if (!createNewPrivate(target)) die("duplicate entry during unpack: " + entryPath(e.sec, e.name));
            std::ofstream out(target, std::ios::binary | std::ios::trunc);
            if (!out) die("cannot write: " + S(target));
            try {
                zcfSource src(zcf, h.blobStart, h.salt, h.mk, e);
                Bytes buf(65536);
                Wiper<Bytes> wbuf{buf};
                for (;;) {
                    checkInterrupt();
                    size_t r = src.read(buf.data(), buf.size());
                    if (!r) break;
                    out.write((const char*)buf.data(), (std::streamsize)r);
                    if (!out) die("write failed");
                }
                out.close();
            } catch (...) {
                out.close();
                std::error_code rec;
                fs::remove(target, rec);
                throw;
            }
        }
        std::string fin = S(targetDir);
        if (fs::exists(P(fin))) {
            std::string head = splitextHead(fin);
            std::string tail = splitextTail(fin);
            int i = 1;
            while (fs::exists(P(head + "_" + std::to_string(i) + tail))) i++;
            fin = head + "_" + std::to_string(i) + tail;
        }
        fs::rename(tmpDir, P(fin));
        finalName = fin;
    } catch (...) {
        std::error_code rec;
        fs::remove_all(tmpDir, rec);
        throw;
    }
    std::cout << "Extracted " << h.files.size() << " files to " << finalName << "\n";
}

static void cmdDel(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> targets;
    splitzcfAndInputs(o.items, zcf, targets);
    if (targets.empty()) die("no file specified");
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::set<std::string> byPath;
    for (const auto& e : h.files) byPath.insert(entryPath(e.sec, e.name));
    for (const auto& t : targets)
        if (!byPath.count(t)) die("not found: " + t);
    std::set<std::string> remove(targets.begin(), targets.end());
    std::vector<Entry> all = existingEntries(zcf, h);
    std::vector<Entry> entries;
    for (const auto& e : all)
        if (!remove.count(entryPath(e.sec, e.name))) entries.push_back(e);
    writezcf(zcf, o.pw, entries);
    std::string joined;
    for (size_t i = 0; i < targets.size(); i++) {
        if (i) joined += ", ";
        joined += targets[i];
    }
    std::cout << "Deleted: " << joined << "\n";
}

static void cmdRename(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> rest;
    splitzcfAndInputs(o.items, zcf, rest);
    if (rest.empty() || rest.size() % 2 != 0) die("rename needs old/new pairs");
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::set<std::string> byPath;
    for (const auto& e : h.files) byPath.insert(entryPath(e.sec, e.name));
    std::map<std::string, std::pair<std::vector<std::string>, std::string>> renames;
    for (size_t i = 0; i < rest.size(); i += 2) {
        const std::string& oldp = rest[i];
        const std::string& newp = rest[i + 1];
        if (!byPath.count(oldp)) die("not found: " + oldp);
        if (renames.count(oldp)) die("entry renamed more than once: " + oldp);
        std::vector<std::string> s;
        std::string n;
        parsePath(newp, s, n);
        std::string why;
        if (!namesPortable(s, n, why)) die("rename target is not portable: " + newp + ": " + why);
        renames[oldp] = {s, n};
    }
    std::vector<Entry> all = existingEntries(zcf, h);
    std::vector<Entry> entries;
    for (const auto& e : all) {
        std::string p = entryPath(e.sec, e.name);
        auto it = renames.find(p);
        if (it != renames.end()) {
            entries.push_back({it->second.second, it->second.first, e.size, e.make});
        } else {
            entries.push_back(e);
        }
    }
    writezcf(zcf, o.pw, entries);
    std::cout << "Renamed.\n";
}

static void cmdLs(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> extra;
    splitzcfAndInputs(o.items, zcf, extra);
    if (!extra.empty()) die("unexpected arguments");
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::vector<std::pair<std::string, uint64_t>> rows;
    for (const auto& e : h.files) rows.push_back({entryPath(e.sec, e.name), e.size});
    std::sort(rows.begin(), rows.end());
    size_t width = 1;
    uint64_t sum = 0;
    for (const auto& r : rows) {
        width = std::max(width, std::to_string(r.second).size());
        sum += r.second;
    }
    for (const auto& r : rows) {
        std::string sz = std::to_string(r.second);
        std::cout << std::string(width - sz.size(), ' ') << sz << " " << r.first << "\n";
    }
    std::cout << "Total: " << rows.size() << " files, " << sum << " bytes\n";
}

static void cmdVerify(const std::vector<std::string>& args) {
    Opts o; splitOpts(o, args);
    std::string zcf;
    std::vector<std::string> extra;
    splitzcfAndInputs(o.items, zcf, extra);
    if (!extra.empty()) die("unexpected arguments");
    Header h = readHeaderAndMeta(zcf, o.pw);
    std::error_code ec;
    uint64_t total = fs::file_size(P(zcf), ec);
    if (ec) die("cannot stat zcf file");
    uint64_t blobSize = total - h.blobStart;

    std::vector<const FMeta*> order;
    for (const FMeta& e : h.files) order.push_back(&e);
    std::sort(order.begin(), order.end(), [](const FMeta* a, const FMeta* b) { return a->off < b->off; });
    uint64_t pos = 0;
    for (const FMeta* e : order) {
        if (e->off != pos) die("archive layout is damaged near: " + entryPath(e->sec, e->name));
        pos += e->len;
    }
    if (pos != blobSize) die("archive layout is damaged: unexpected trailing data");

    size_t damaged = 0;
    uint64_t bytes = 0;
    for (const FMeta& e : h.files) {
        checkInterrupt();
        std::string p = entryPath(e.sec, e.name);
        std::string why;
        if (!namesPortable(e.sec, e.name, why)) {
            ++damaged;
            std::cerr << "damaged: " << p << ": " << why << "\n";
            continue;
        }
        try {
            zcfSource src(zcf, h.blobStart, h.salt, h.mk, e);
            Bytes buf(65536);
            Wiper<Bytes> wbuf{buf};
            uint64_t got = 0;
            for (;;) {
                checkInterrupt();
                size_t r = src.read(buf.data(), buf.size());
                if (!r) break;
                got += r;
            }
            if (got != e.size) die(kCorrupt);
        } catch (const Fail& ex) {
            if (gInterrupted) throw;
            ++damaged;
            std::cerr << "damaged: " << p << ": " << ex.what() << "\n";
            continue;
        }
        bytes += e.size;
    }
    if (damaged) die("verification failed: " + std::to_string(damaged) + " of " + std::to_string(h.files.size()) + " entries damaged");
    std::cout << "OK: " << h.files.size() << " entries verified, " << bytes << " bytes\n";
}

static void run(const std::vector<std::string>& a) {
    if (a.empty()) {
        std::cout << "Zetern Containers\n";
        std::cout << "  -c    main.zcf [--force] [--save-password FILE]\n";
        std::cout << "  -caaf main.zcf f1 dir1 dir2 ... [--force] [--save-password FILE]\n";
        std::cout << "  -af   main.zcf f1 dir1 ... [--skip-existing | --overwrite]\n";
        std::cout << "  -aaf  main.zcf [--skip-existing | --overwrite] [exclude_glob ...]\n";
        std::cout << "  -u    main.zcf\n";
        std::cout << "  -df   main.zcf path1 path2 ...\n";
        std::cout << "  --rf  main.zcf old1 new1 old2 new2 ...\n";
        std::cout << "  ls    main.zcf\n";
        std::cout << "  verify main.zcf\n";
        std::cout << "password: stdin or interactive prompt\n";
        return;
    }
    const std::string& c = a[0];
    std::vector<std::string> rest(a.begin() + 1, a.end());
    if (c == "-c") {
        Opts o; splitOpts(o, rest, false);
        if (o.items.size() != 1) die("-c takes exactly one path");
        cmdCreate(o.items[0], o.force, o.savePw);
    } else if (c == "-caaf") {
        Opts o; splitOpts(o, rest, false);
        if (o.items.size() < 2) die("-caaf needs target and inputs");
        cmdCaaf(o.items[0], std::vector<std::string>(o.items.begin() + 1, o.items.end()), o.force, o.savePw);
    } else if (c == "-af") {
        cmdAf(rest);
    } else if (c == "-aaf") {
        cmdAaf(rest);
    } else if (c == "-u") {
        cmdUnpack(rest);
    } else if (c == "-df") {
        cmdDel(rest);
    } else if (c == "--rf") {
        cmdRename(rest);
    } else if (c == "ls") {
        cmdLs(rest);
    } else if (c == "verify") {
        cmdVerify(rest);
    } else {
        die("unknown command: " + c);
    }
}

int main(int argc, char** argv) {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::vector<std::string> a(argv + 1, argv + argc);
    try {
        run(a);
    } catch (const Fail& e) {
        std::cerr << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}