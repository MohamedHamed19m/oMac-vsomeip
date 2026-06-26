#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// OMacFooter — 24-byte struct appended to the END of every SOME/IP payload.
//
// Legacy nodes that do not understand oMac simply read the payload bytes they
// expect and never look at the trailing footer, so backward compatibility is
// preserved without any change to the SOME/IP message header.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct OMacFooter {
    uint32_t magic     = 0x4F4D4143;  // "OMAC" — sentinel to detect footer presence
    uint16_t domain_id = 0;           // sender's functional domain
    uint16_t method_id = 0;           // which method triggered this call
    uint8_t  mac[16]   = {};          // AES-128-CMAC authentication tag

    // total = 4 + 2 + 2 + 16 = 24 bytes
};
#pragma pack(pop)

static_assert(sizeof(OMacFooter) == 24, "OMacFooter must be exactly 24 bytes");

constexpr uint32_t OMAC_MAGIC = 0x4F4D4143;

// ---------------------------------------------------------------------------
// Helper: append a footer to the end of a raw payload buffer.
// ---------------------------------------------------------------------------
inline void footer_append(std::vector<uint8_t>& buf, const OMacFooter& footer)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&footer);
    buf.insert(buf.end(), p, p + sizeof(OMacFooter));
}

// ---------------------------------------------------------------------------
// Helper: check whether the last sizeof(OMacFooter) bytes look like a footer.
// Returns false if the buffer is too short or the magic is wrong.
// ---------------------------------------------------------------------------
inline bool footer_present(const std::vector<uint8_t>& buf)
{
    if (buf.size() < sizeof(OMacFooter)) return false;
    uint32_t magic = 0;
    std::memcpy(&magic, buf.data() + buf.size() - sizeof(OMacFooter), 4);
    return magic == OMAC_MAGIC;
}

// ---------------------------------------------------------------------------
// Helper: extract the footer from the tail of the buffer (no bounds check —
// call footer_present() first).
// ---------------------------------------------------------------------------
inline OMacFooter footer_extract(const std::vector<uint8_t>& buf)
{
    OMacFooter f;
    std::memcpy(&f, buf.data() + buf.size() - sizeof(OMacFooter), sizeof(OMacFooter));
    return f;
}

// ---------------------------------------------------------------------------
// Helper: return only the payload bytes (everything before the footer).
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> payload_without_footer(const std::vector<uint8_t>& buf)
{
    if (buf.size() < sizeof(OMacFooter)) return buf;
    return std::vector<uint8_t>(buf.begin(), buf.end() - sizeof(OMacFooter));
}
