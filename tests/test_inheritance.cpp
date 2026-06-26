// test_inheritance.cpp — mock proof of the paper's SecuredMessageImpl model

#include "crypto.hpp"
#include "footer.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

static const std::array<uint8_t, 16> DEMO_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

namespace mock_vsomeip {

class serializer {
public:
    void write(const uint8_t* data, std::size_t len) {
        buffer_.insert(buffer_.end(), data, data + len);
    }

    const std::vector<uint8_t>& buffer() const { return buffer_; }

private:
    std::vector<uint8_t> buffer_;
};

class deserializer {
public:
    explicit deserializer(std::vector<uint8_t> data) : buffer_(std::move(data)) {}

    const std::vector<uint8_t>& buffer() const { return buffer_; }

private:
    std::vector<uint8_t> buffer_;
};

class serializable {
public:
    virtual ~serializable() = default;
    virtual bool serialize(serializer* out) const = 0;
};

class deserializable {
public:
    virtual ~deserializable() = default;
    virtual bool deserialize(deserializer* in) = 0;
};

class message_base : public serializable, public deserializable {
public:
    void set_domain(uint16_t domain) { domain_id_ = domain; }
    void set_method(uint16_t method) { method_id_ = method; }
    uint16_t domain() const { return domain_id_; }
    uint16_t method() const { return method_id_; }

protected:
    uint16_t domain_id_ = 0;
    uint16_t method_id_ = 0;
};

class message : public message_base {
public:
    void set_payload(std::vector<uint8_t> data) { payload_ = std::move(data); }
    const std::vector<uint8_t>& payload() const { return payload_; }

protected:
    std::vector<uint8_t> payload_;
};

class message_impl : public message {
public:
    bool serialize(serializer* out) const override {
        if (!payload_.empty()) {
            out->write(payload_.data(), payload_.size());
        }
        return true;
    }

    bool deserialize(deserializer* in) override {
        payload_ = in->buffer();
        return true;
    }
};

class SecuredMessageImpl : public message_impl {
public:
    bool serialize(serializer* out) const override {
        if (!message_impl::serialize(out)) {
            return false;
        }

        OMacFooter footer;
        footer.domain_id = domain();
        footer.method_id = method();
        crypto::sign_message(out->buffer().data(), out->buffer().size(), footer);

        out->write(reinterpret_cast<const uint8_t*>(&footer), sizeof(footer));
        return true;
    }

    bool deserialize(deserializer* in) override {
        const auto& wire = in->buffer();
        if (wire.size() < sizeof(OMacFooter)) {
            return false;
        }

        OMacFooter footer;
        std::memcpy(&footer, wire.data() + wire.size() - sizeof(OMacFooter), sizeof(footer));
        if (footer.magic != OMAC_MAGIC) {
            return false;
        }

        const std::size_t payload_len = wire.size() - sizeof(OMacFooter);
        if (!crypto::verify_message(wire.data(), payload_len, footer)) {
            return false;
        }

        set_domain(footer.domain_id);
        set_method(footer.method_id);
        set_payload(std::vector<uint8_t>(wire.begin(), wire.begin() + payload_len));
        return true;
    }
};

} // namespace mock_vsomeip

static void test_round_trip()
{
    mock_vsomeip::SecuredMessageImpl msg;
    msg.set_domain(0x1234);
    msg.set_method(0x5678);
    msg.set_payload({'H', 'e', 'l', 'l', 'o'});

    mock_vsomeip::serializer out;
    assert(msg.serialize(&out));

    const auto& wire = out.buffer();
    assert(wire.size() == 5 + sizeof(OMacFooter));
    assert(footer_present(wire));

    mock_vsomeip::SecuredMessageImpl decoded;
    mock_vsomeip::deserializer in(wire);
    assert(decoded.deserialize(&in));
    assert(decoded.payload() == std::vector<uint8_t>({'H', 'e', 'l', 'l', 'o'}));
    assert(decoded.domain() == 0x1234);
    assert(decoded.method() == 0x5678);

    std::cout << "[PASS] SecuredMessageImpl round-trip preserves payload and footer\n";
}

static void test_tamper_blocked()
{
    mock_vsomeip::SecuredMessageImpl msg;
    msg.set_domain(0x0001);
    msg.set_method(0x0002);
    msg.set_payload({'D', 'A', 'T', 'A'});

    mock_vsomeip::serializer out;
    assert(msg.serialize(&out));

    std::vector<uint8_t> wire = out.buffer();
    wire[0] ^= 0xFF;

    mock_vsomeip::SecuredMessageImpl decoded;
    mock_vsomeip::deserializer in(wire);
    assert(!decoded.deserialize(&in));

    std::cout << "[PASS] SecuredMessageImpl rejects tampered wire data\n";
}

int main()
{
    crypto::set_key(DEMO_KEY);

    std::cout << "=== test_inheritance ===\n";
    test_round_trip();
    test_tamper_blocked();
    std::cout << "All inheritance tests passed.\n";
    return 0;
}
