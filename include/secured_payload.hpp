// secured_payload.hpp
//
// Public helper for attaching and verifying the 24-byte OMacFooter.
//
// The public vsomeip headers available in this repo do not expose the internal
// serializer/deserializer types needed for a direct middleware override, so the
// implementation works at the payload boundary:
//   - encode_wire() produces signed wire bytes.
//   - make_outbound() returns a standard vsomeip payload object containing the
//     signed wire bytes.
//   - decode_incoming() validates the footer and strips it back to application
//     bytes for the reference monitor and application logic.
//
#pragma once

#include "footer.hpp"
#include "crypto.hpp"

#include <vsomeip/vsomeip.hpp>

#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace omac {

// ---------------------------------------------------------------------------
// SecuredPayload � helper for building and decoding footer-protected payloads.
// ---------------------------------------------------------------------------
class SecuredPayload {
public:
    // Build signed wire bytes from application data plus footer metadata.
    static std::vector<uint8_t> encode_wire(const std::vector<uint8_t>& app_data,
                                            uint16_t domain_id,
                                            uint16_t method_id)
    {
        OMacFooter footer;
        footer.domain_id = domain_id;
        footer.method_id = method_id;
        crypto::sign_message(app_data.data(), app_data.size(), footer);

        std::vector<uint8_t> wire = app_data;
        const uint8_t* footer_bytes = reinterpret_cast<const uint8_t*>(&footer);
        wire.insert(wire.end(), footer_bytes, footer_bytes + sizeof(OMacFooter));
        return wire;
    }

    // Build a wire-format payload and hand it back as a standard vsomeip
    // payload object so callers can send it without depending on internals.
    static std::shared_ptr<vsomeip::payload>
    make_outbound(const std::vector<uint8_t>& app_data,
                  uint16_t domain_id,
                  uint16_t method_id)
    {
        auto wire = encode_wire(app_data, domain_id, method_id);
        auto payload = vsomeip::runtime::get()->create_payload();
        payload->set_data(wire);
        return payload;
    }

    // Decode a wire-format payload into application bytes plus footer.
    // Returns false if the footer is missing, malformed, or fails CMAC.
    static bool decode_incoming(const std::vector<uint8_t>& wire_buf,
                                std::vector<uint8_t>& app_data,
                                OMacFooter& footer)
    {
        if (wire_buf.size() < sizeof(OMacFooter)) {
            std::cout << "[SecuredPayload] BLOCK — payload too short to contain footer\n";
            return false;
        }

        std::memcpy(&footer, wire_buf.data() + wire_buf.size() - sizeof(OMacFooter),
                    sizeof(OMacFooter));

        if (footer.magic != OMAC_MAGIC) {
            std::cout << "[SecuredPayload] BLOCK — no OMacFooter magic in message\n";
            return false;
        }

        const size_t app_len = wire_buf.size() - sizeof(OMacFooter);
        if (!crypto::verify_message(wire_buf.data(), app_len, footer)) {
            std::cout << "[SecuredPayload] BLOCK — CMAC verification failed\n";
            return false;
        }

        app_data.assign(wire_buf.begin(), wire_buf.begin() + app_len);
        return true;
    }
};

} // namespace omac
