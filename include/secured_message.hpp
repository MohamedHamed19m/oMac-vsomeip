// secured_message.hpp  — paper-faithful implementation
//
// SecuredMessage wraps a vsomeip::message and forces all outbound
// messages to use a SecuredPayload, so that the footer is automatically
// appended during serialization without the application code having
// to call footer_append() manually.
//
// Inbound: when you call check_inbound(), the payload is cast to
// SecuredPayload so the monitor can inspect the already-verified footer.
//
#pragma once

#include "secured_payload.hpp"
#include "reference_monitor.hpp"

#include <vsomeip/vsomeip.hpp>

#include <iostream>
#include <memory>
#include <string>

namespace omac {

// ---------------------------------------------------------------------------
// SecuredMessage — composites a vsomeip::message with a SecuredPayload.
//
// Usage (outbound):
//   auto msg = omac::SecuredMessage::create_request(app, service, instance, method);
//   msg->set_app_data(buf, domain_id, method_id);
//   app->send(msg->raw());   // footer is appended during vsomeip serialization
//
// Usage (inbound inside a message handler):
//   auto smsg = omac::SecuredMessage::from_incoming(msg);
//   if (!smsg) { /* no footer */ return; }
//   bool ok = smsg->check(monitor, from, to, method_name);
// ---------------------------------------------------------------------------
class SecuredMessage {
public:
    // -----------------------------------------------------------------------
    // Outbound factory: build a request with a SecuredPayload
    // -----------------------------------------------------------------------
    static std::shared_ptr<SecuredMessage>
    create_request(std::shared_ptr<vsomeip::application>& app,
                   vsomeip::service_t  service,
                   vsomeip::instance_t instance,
                   vsomeip::method_t   method)
    {
        auto raw = vsomeip::runtime::get()->create_request();
        raw->set_service(service);
        raw->set_instance(instance);
        raw->set_method(method);

        return std::make_shared<SecuredMessage>(raw);
    }

    // -----------------------------------------------------------------------
    // Inbound factory: try to interpret an incoming message's payload
    // as a SecuredPayload (already deserialized by vsomeip).
    //
    // Because vsomeip constructs its own payload objects internally during
    // deserialization (not via our SecuredPayload), we re-interpret the raw
    // bytes ourselves: extract the buffer from the standard payload and run
    // the SecuredPayload deserialization logic on it.
    //
    // Returns nullptr if the payload fails verification.
    // -----------------------------------------------------------------------
    static std::shared_ptr<SecuredMessage>
    from_incoming(const std::shared_ptr<vsomeip::message>& msg)
    {
        auto pl = msg->get_payload();
        if (!pl || pl->get_length() == 0) {
            std::cout << "[SecuredMessage] Incoming message has no payload\n";
            return nullptr;
        }

        // Copy the raw wire bytes (app bytes + footer) into our deserializer
        std::vector<uint8_t> wire(pl->get_data(), pl->get_data() + pl->get_length());

        if (wire.size() < sizeof(OMacFooter)) {
            std::cout << "[SecuredMessage] Payload too short for footer\n";
            return nullptr;
        }

        // Extract and verify the footer manually (mirrors SecuredPayload::deserialize)
        OMacFooter footer;
        std::memcpy(&footer, wire.data() + wire.size() - sizeof(OMacFooter),
                    sizeof(OMacFooter));

        if (footer.magic != OMAC_MAGIC) {
            std::cout << "[SecuredMessage] BLOCK — missing OMacFooter magic\n";
            return nullptr;
        }

        const size_t app_len = wire.size() - sizeof(OMacFooter);
        if (!crypto::verify_message(wire.data(), app_len, footer)) {
            std::cout << "[SecuredMessage] BLOCK — CMAC verification failed\n";
            return nullptr;
        }

        // Build a verified SecuredMessage
        auto sm = std::make_shared<SecuredMessage>(msg);
        sm->app_data_.assign(wire.begin(), wire.begin() + app_len);
        sm->footer_   = footer;
        sm->verified_ = true;
        return sm;
    }

    // -----------------------------------------------------------------------
    // Set application payload for an outbound message (before send)
    // -----------------------------------------------------------------------
    void set_app_data(const std::vector<uint8_t>& data,
                      uint16_t domain_id,
                      uint16_t method_id)
    {
        auto sp = SecuredPayload::make_outbound(data, domain_id, method_id);
        raw_->set_payload(sp);
        // Also cache locally for convenience
        app_data_ = data;
        footer_.domain_id = domain_id;
        footer_.method_id = method_id;
    }

    // -----------------------------------------------------------------------
    // Run the automaton check after successful CMAC verification
    // -----------------------------------------------------------------------
    bool check(ReferenceMonitor& monitor,
               const std::string& from,
               const std::string& to,
               const std::string& method_name)
    {
        if (!verified_) {
            std::cout << "[SecuredMessage] check() called on unverified message — BLOCK\n";
            return false;
        }
        return monitor.check(wire_buf_with_footer(), from, to, method_name);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    std::shared_ptr<vsomeip::message> raw()        const { return raw_; }
    const std::vector<uint8_t>&       app_data()   const { return app_data_; }
    const OMacFooter&                 footer()     const { return footer_; }
    bool                              verified()   const { return verified_; }

public:
    explicit SecuredMessage(std::shared_ptr<vsomeip::message> raw)
        : raw_(std::move(raw)) {}

private:

    // Reconstruct the wire buffer (app_data + footer) for ReferenceMonitor::check
    std::vector<uint8_t> wire_buf_with_footer() const {
        std::vector<uint8_t> buf = app_data_;
        const uint8_t* fp = reinterpret_cast<const uint8_t*>(&footer_);
        buf.insert(buf.end(), fp, fp + sizeof(OMacFooter));
        return buf;
    }

    std::shared_ptr<vsomeip::message> raw_;
    std::vector<uint8_t>              app_data_;
    OMacFooter                        footer_ = {};
    bool                              verified_ = false;
};

} // namespace omac
