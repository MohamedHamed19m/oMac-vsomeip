//
// safety_uc.cpp — Safety µC: protected SOME/IP server endpoint
//
// Simulates the Safety micro-controller described in the oMac paper.
// Offers two services:
//   - SafetyuC::Diag  (service 0x3333, method 0x0001 = invoke_Diag)
//   - SafetyuC::Ctrl  (service 0x4444, method 0x0001 = invoke_Ctrl)
//
// Runs its own local ReferenceMonitor so it can independently validate
// every call it receives — defence-in-depth against a compromised app_up.
//
// Usage:
//   ./safety_uc <path/to/tcu_rd_rc_policy.json>
//
// vsomeip config (set via env var):
//   VSOMEIP_CONFIGURATION=examples/config/vsomeip-safety.json
//

#include "reference_monitor.hpp"
#include "crypto.hpp"
#include "footer.hpp"

#include <vsomeip/vsomeip.hpp>

#include <array>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// SOME/IP identifiers
// ---------------------------------------------------------------------------
constexpr vsomeip::service_t  DIAG_SERVICE  = 0x3333;
constexpr vsomeip::service_t  CTRL_SERVICE  = 0x4444;
constexpr vsomeip::instance_t INSTANCE      = 0x0001;
constexpr vsomeip::method_t   METHOD_DIAG   = 0x0001;  // invoke_Diag
constexpr vsomeip::method_t   METHOD_CTRL   = 0x0001;  // invoke_Ctrl

// Demo shared key — in production this would come from a secure key store
static const std::array<uint8_t, 16> DEMO_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ---------------------------------------------------------------------------
// SafetyUC application
// ---------------------------------------------------------------------------
class SafetyUC {
public:
    explicit SafetyUC(const std::string& policy_path)
        : monitor_(policy_path)
        , app_(vsomeip::runtime::get()->create_application("safety_uc"))
    {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[SafetyUC] vsomeip init failed\n";
            return false;
        }

        // Register Diag service handler
        app_->register_message_handler(DIAG_SERVICE, INSTANCE, METHOD_DIAG,
            [this](const std::shared_ptr<vsomeip::message>& msg) {
                on_message(msg, "AppuP::RD", "SafetyuC::Diag", "invoke_Diag", "DIAG");
            });

        // Register Ctrl service handler
        app_->register_message_handler(CTRL_SERVICE, INSTANCE, METHOD_CTRL,
            [this](const std::shared_ptr<vsomeip::message>& msg) {
                on_message(msg, "AppuP::RC", "SafetyuC::Ctrl", "invoke_Ctrl", "CTRL");
            });

        // Offer both services
        app_->offer_service(DIAG_SERVICE, INSTANCE);
        app_->offer_service(CTRL_SERVICE, INSTANCE);

        std::cout << "[SafetyUC] Services offered — waiting for calls\n";
        return true;
    }

    void start() { app_->start(); }
    void stop()  { app_->stop_offer_service(DIAG_SERVICE, INSTANCE);
                   app_->stop_offer_service(CTRL_SERVICE, INSTANCE);
                   app_->stop(); }

private:
    ReferenceMonitor monitor_;
    std::shared_ptr<vsomeip::application> app_;

    void on_message(const std::shared_ptr<vsomeip::message>& msg,
                    const std::string& from,
                    const std::string& to,
                    const std::string& method,
                    const std::string& label)
    {
        // Extract raw payload buffer from vsomeip message
        auto pl = msg->get_payload();
        std::vector<uint8_t> buf(pl->get_data(), pl->get_data() + pl->get_length());

        std::cout << "[SafetyUC] Received " << label
                  << " call (" << buf.size() << " bytes)\n";

        bool allowed = monitor_.check(buf, from, to, method);
        if (allowed) {
            // Strip footer to get the real application bytes
            auto payload = payload_without_footer(buf);
            std::string data(payload.begin(), payload.end());
            std::cout << "[SafetyUC] Executing " << label
                      << " — data: \"" << data << "\"\n";
        } else {
            std::cerr << "[SafetyUC] *** SECURITY VIOLATION — " << label
                      << " call REJECTED ***\n";
        }
    }
};

// ---------------------------------------------------------------------------
// Signal handler for clean shutdown
// ---------------------------------------------------------------------------
static std::shared_ptr<SafetyUC> g_app;
static void on_signal(int) { if (g_app) g_app->stop(); }

// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <policy.json>\n";
        return 1;
    }

    crypto::set_key(DEMO_KEY);

    g_app = std::make_shared<SafetyUC>(argv[1]);
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    if (!g_app->init()) return 1;
    g_app->start();  // blocks until stop() is called
    return 0;
}
