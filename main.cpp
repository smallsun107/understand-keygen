// understand-keygen — SciTools Understand (Helios) keygen
//
// Two schemes, both recovered from the Understand Mach-O binary:
//
//   instatrial (device-free)           LicenseKey::generateInstatrial   0x101a5ece0
//   offline reply code (machine-bound) LicenseKey::generateReplyCode    0x101a60220
//   salt initialiser                   InitFunc_568                    0x101a61600
//
//   salt_A = "MwD6-Gi2U-B8dc-23ed"   @ 0x1028e7f50   (19 bytes)
//   salt_B = "MwD6Gi2UB8dc23ed"      @ 0x1028e7f70   (17 bytes)
//   productId = "y7cI-HEtm"
//
// Every code is:  concat(ascii) -> hash -> lowercase hex -> drop the ambiguous
// glyphs 0 1 i l o -> trim -> UPPERCASE.
//
//   instatrial:
//     h    = strip( MD5( "yyyyMMdd"(UTC) + salt_B + build ) )
//     code = upper( truncate(10)( remove(1,3)( h ) ) )
//
//   offline reply code:
//     part1 = SHA1( salt_A + productId + machineId + secondaryId + name + requestSecs )
//     s1    = upper( clean5(part1) )
//     code  = upper( clean10( MD5( salt_B + s1 + expiry + maintenance ) ) )

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <ctime>
#include <string>
#include <iostream>

// =============================================================================
// Hashing (MD5 + SHA-1, self contained)
// =============================================================================
namespace {

inline uint32_t rotl32(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

// shared streaming / padding logic; Derived provides block() and state
template <class Derived>
struct Hasher {
    uint64_t len = 0;
    uint8_t  buf[64];
    size_t   buflen = 0;

    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - buflen; if (take > n) take = n;
            std::memcpy(buf + buflen, p, take);
            buflen += take; p += take; n -= take;
            if (buflen == 64) { static_cast<Derived*>(this)->block(buf); buflen = 0; }
        }
    }
    void finish_pad() {                       // append 0x80, zeros, 64-bit bit-length
        uint64_t bits = len * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        uint8_t z = 0;
        while (buflen != 56) update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i)
            lb[i] = static_cast<uint8_t>(bits >> (8 * (static_cast<Derived*>(this)->length_little_endian() ? i : (7 - i))));
        update(lb, 8);
    }
};

struct MD5 : Hasher<MD5> {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    static constexpr bool length_little_endian() { return true; }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,
            0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
            0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,
            0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,
            0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
            0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,
            0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
            0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
            0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
        static const int S[64] = {
            7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
            5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
            4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
            6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
        uint32_t M[16];
        for (int i = 0; i < 16; ++i)
            M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
                   ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; ++i) {
            uint32_t F; int g;
            if (i < 16)      { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D;          g = (3*i + 5) & 15; }
            else             { F = C ^ (B | ~D);       g = (7*i) & 15; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B; B = B + rotl32(F, S[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }

    std::string hex() {
        finish_pad();
        char out[33];
        for (int i = 0, k = 0; i < 4; ++i, k += 8) {
            uint32_t v = i == 0 ? a0 : i == 1 ? b0 : i == 2 ? c0 : d0;
            std::snprintf(out + k, 9, "%08x",
                          ((v & 0xff) << 24) | ((v & 0xff00) << 8) |
                          ((v >> 8) & 0xff00) | ((v >> 24) & 0xff));
        }
        return std::string(out, 32);
    }
};

struct SHA1 : Hasher<SHA1> {
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    static constexpr bool length_little_endian() { return false; }

    void block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
                   ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
        for (int i = 16; i < 80; ++i)
            w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    std::string hex() {
        finish_pad();
        char out[41];
        for (int i = 0; i < 5; ++i) std::snprintf(out + i*8, 9, "%08x", h[i]);
        return std::string(out, 40);
    }
};

std::string md5_hex(const std::string& d)  { MD5  h; h.update((const uint8_t*)d.data(), d.size()); return h.hex(); }
std::string sha1_hex(const std::string& d) { SHA1 h; h.update((const uint8_t*)d.data(), d.size()); return h.hex(); }

} // namespace

// =============================================================================
// Recovered constants
// =============================================================================
static constexpr const char* SALT_A  = "MwD6-Gi2U-B8dc-23ed";   // 0x1028e7f50
static constexpr const char* SALT_B  = "MwD6Gi2UB8dc23ed";      // 0x1028e7f70
static constexpr const char* PRODUCT = "y7cI-HEtm";             // mProductId
static constexpr const char* BUILD   = "1264";                  // buildNumber

// =============================================================================
// Code construction helpers
// =============================================================================
static std::string upper(std::string s) {
    for (char& c : s) c = (char)std::toupper((unsigned char)c);
    return s;
}

// remove every occurrence of the ambiguous glyphs 0 1 i l o
static std::string strip_confusables(const std::string& h) {
    std::string r;
    r.reserve(h.size());
    for (char c : h)
        if (!(c == '0' || c == '1' || c == 'i' || c == 'l' || c == 'o')) r.push_back(c);
    return r;
}

// QString::remove(1,3) then QString::truncate(limit)
static std::string clean(const std::string& h, size_t limit, bool remove13) {
    std::string s = strip_confusables(h);
    if (remove13 && s.size() > 1) s.erase(1, 3);
    if (s.size() > limit) s.resize(limit);
    return s;
}

// =============================================================================
// Scheme 1 — instatrial (device-free)
//   testInstatrialCode accepts the UTC date of today-5 .. today; valid 15 days.
// =============================================================================
static std::string generate_instatrial(const std::string& date_yyyymmdd,
                                       const std::string& build = BUILD) {
    return upper(clean(md5_hex(date_yyyymmdd + SALT_B + build), 10, true));
}

// =============================================================================
// Scheme 2 — offline reply code (machine-bound)
// =============================================================================
static std::string generate_reply_code(const std::string& machine_id,
                                       const std::string& secondary_id,
                                       const std::string& machine_name,
                                       const std::string& request_secs,
                                       const std::string& expiry,
                                       const std::string& maintenance = "") {
    std::string part1 = std::string(SALT_A) + PRODUCT + machine_id +
                        secondary_id + machine_name + request_secs;
    std::string s1 = upper(clean(sha1_hex(part1), 5, true));
    return upper(clean(md5_hex(std::string(SALT_B) + s1 + expiry + maintenance), 10, false));
}

static std::string utc_date_offset(int days) {   // UTC 'yyyyMMdd' for today+days
    time_t t = time(nullptr) + (time_t)days * 86400;
    struct tm tmv; gmtime_r(&t, &tmv);
    char b[16]; std::strftime(b, sizeof(b), "%Y%m%d", &tmv);
    return b;
}

// =============================================================================
// CLI
// =============================================================================
static void usage(const char* p) {
    std::cout <<
"Usage:\n"
"  " << p << " instatrial [build=1264] [yyyymmdd]   instatrial code (UTC today, device-free)\n"
"  " << p << " offline  <expiry> <machineId> <secondaryId> <name> <requestSecs> [maintenance]\n"
"  " << p << " verify   <code> [build=1264]         check an instatrial code\n"
"\n"
"Examples:\n"
"  " << p << " instatrial\n"
"  " << p << " offline 20351231 <machineId> <secondaryId> <name> <requestSecs>\n"
"  " << p << " verify <code>\n";
}

int main(int argc, char** argv) {
    const char* prog = std::strrchr(argv[0], '/'); prog = prog ? prog + 1 : argv[0];
    if (argc < 2) { usage(prog); return 1; }

    std::string mode = argv[1];

    if (mode == "instatrial") {
        std::string build = argc > 2 ? argv[2] : BUILD;
        std::string date  = argc > 3 ? argv[3] : utc_date_offset(0);
        std::string code  = generate_instatrial(date, build);
        std::cout << "Date    : " << date << "\n"
                  << "Build   : " << build << "\n"
                  << "Code    : " << code << "\n"
                  << "Install : und -instatrialcode " << code << " " << build << "\n";
        return 0;
    }

    if (mode == "offline") {
        if (argc < 7) {
            std::cerr << "offline needs: <expiry> <machineId> <secondaryId> <name> "
                         "<requestSecs> [maintenance]\n";
            return 1;
        }
        std::string expiry = argv[2], mid = argv[3], sid = argv[4], name = argv[5];
        std::string req = argv[6], maint = argc > 7 ? argv[7] : "";
        std::string code = generate_reply_code(mid, sid, name, req, expiry, maint);
        std::cout << "Machine : " << mid << "\n"
                  << "Sec     : " << sid << "\n"
                  << "Name    : " << name << "\n"
                  << "Req     : " << req << "\n"
                  << "Expiry  : " << expiry << "\n"
                  << "Code    : " << code << "\n"
                  << "Install : und -setofflinereplycode " << code
                  << " -setofflinereplydate " << expiry << "\n";
        return 0;
    }

    if (mode == "verify") {
        if (argc < 3) { std::cerr << "verify needs <code> [build]\n"; return 1; }
        std::string code  = upper(argv[2]);
        std::string build = argc > 3 ? argv[3] : BUILD;
        std::string match;
        for (int d = 5; d >= 0; --d) {                 // today-5 .. today (UTC)
            std::string day = utc_date_offset(-d);
            if (generate_instatrial(day, build) == code) { match = day; break; }
        }
        std::cout << "Code    : " << code << "\n"
                  << "Build   : " << build << "\n"
                  << "Result  : " << (match.empty() ? "INVALID" : "VALID")
                  << (match.empty() ? "" : "  (" + match + ")") << "\n";
        return match.empty() ? 1 : 0;
    }

    usage(prog);
    return 1;
}
