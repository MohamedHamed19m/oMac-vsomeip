# Design Plan: oMac-vsomeip (Paper-Specific Middleware-Level Integration)

This document outlines the design for the **Paper-Specific Middleware-Level Integration** on the `paper-inheritance` branch. This architecture replicates the exact UML class inheritance and virtual method overriding described in Section 4 of the research paper.

---

## 1. Architectural Model (Inheritance-Based)

Instead of using application-level helper functions (composition), this model integrates the `OMacFooter` directly into the message serialization/deserialization pipeline of the `vsomeip` middleware.

```
       +------------------------------------------+
       |           vsomeip::serializable          |
       +------------------------------------------+
                             ^
                             | (inherits)
       +------------------------------------------+
       |         vsomeip::message_base_impl       |
       +------------------------------------------+
                             ^
                             | (inherits)
       +------------------------------------------+
       |         vsomeip::message_impl            |
       +------------------------------------------+
                             ^
                             | (inherits)
       +------------------------------------------+
       |            SecuredMessageImpl            |
       +------------------------------------------+
       | + serialize(serializer*) : bool          |
       | + deserialize(deserializer*) : bool      |
       +------------------------------------------+
```

---

## 2. Core Implementation Strategy

Because `vsomeip`'s internal classes `serializer` and `deserializer` are only forward-declared in public headers (`vsomeip/internal/serializable.hpp` and `vsomeip/internal/deserializable.hpp`), compiling a subclass outside the `vsomeip` library codebase is not possible.

To prove the inheritance-based concepts, we will implement:
1. **Mock Serializer/Deserializer classes** under a `mock_vsomeip` namespace for local compilation and unit tests.
2. **`SecuredMessageImpl` Class**: Extends `vsomeip::message_impl` (or our mock equivalent) and overrides the `serialize` and `deserialize` methods.
3. **Reference Monitor Integration Hooks**: Plugs the security verification directly inside `deserialize`, dropping invalid messages before they reach the application.

---

## 3. Class Design

### `SecuredMessageImpl`
Inherits from standard message representation and overrides serialization/deserialization.

```cpp
namespace omac {

class SecuredMessageImpl : public vsomeip::message_impl {
public:
    // Overrides standard serialization to append the 24-byte OMacFooter
    bool serialize(vsomeip::serializer* _to) const override {
        // 1. Call parent serialize() to write standard SOME/IP fields & payload
        if (!vsomeip::message_impl::serialize(_to)) return false;

        // 2. Fetch serialized buffer, calculate CMAC tag, and pack OMacFooter
        OMacFooter footer;
        footer.domain_id = this->get_domain();
        footer.method_id = this->get_calling_method();
        crypto::sign_message(_to->get_data(), _to->get_length(), footer);

        // 3. Append footer to serializer buffer
        _to->write(reinterpret_cast<const uint8_t*>(&footer), sizeof(footer));
        return true;
    }

    // Overrides standard deserialization to extract, verify, and strip OMacFooter
    bool deserialize(vsomeip::deserializer* _from) override {
        // 1. Extract the last 24 bytes from the deserializer's stream
        size_t total_length = _from->get_remaining_length();
        if (total_length < sizeof(OMacFooter)) return false;

        OMacFooter footer;
        _from->peek_back(reinterpret_cast<uint8_t*>(&footer), sizeof(footer));

        // 2. Verify footer presence via magic number
        if (footer.magic != OMAC_MAGIC) return false;

        // 3. Verify CMAC signature of the data preceding the footer
        size_t payload_len = total_length - sizeof(OMacFooter);
        bool mac_ok = crypto::verify_message(_from->get_data(), payload_len, footer);
        if (!mac_ok) return false; // Drop message immediately

        // 4. Temporarily restrict the deserializer stream length to exclude the footer,
        // and call the parent deserialize() to parse standard SOME/IP fields
        _from->set_limit(payload_len);
        bool result = vsomeip::message_impl::deserialize(_from);
        _from->clear_limit();

        return result;
    }
};

} // namespace omac
```

---

## 4. Key Differences from Flat MVP

| Feature | Flat MVP (composition) | Paper-Specific (inheritance) |
|---|---|---|
| **Footer Insertion** | Done explicitly at application level (`footer_append`) before sending. | Handled implicitly during middleware serialization (`serialize`). |
| **Verification Gate** | Done explicitly in app handlers by passing raw payload to `ReferenceMonitor::check`. | Handled implicitly during middleware deserialization (`deserialize`). |
| **Dependency** | Compiles with standard public `vsomeip3` headers. | Requires access to internal `vsomeip` serialization headers/library. |
| **Safety Hook** | Bypassed calls drop at application level. | Bypassed/invalid calls fail to deserialize and drop at middleware level. |

---

## 5. Branch Deliverables Plan

1. **`mock/` directory**: Define mock classes for `vsomeip::serializer`, `vsomeip::deserializer`, `vsomeip::message_impl`, etc., to allow standalone compilation on WSL.
2. **`secured_message_impl`**: Implement `SecuredMessageImpl` overriding mock/actual `serialize` and `deserialize` methods.
3. **`test_inheritance`**: Create a test suite verifying that when `SecuredMessageImpl` is serialized, a 24-byte footer is correctly appended, signed, verified, and stripped during deserialization.
