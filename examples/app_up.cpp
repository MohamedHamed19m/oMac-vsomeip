//
// app_up.cpp — App µP: SOME/IP broker with reference monitor
//
// Simulates the Application micro-processor described in the oMac paper.
//
// Role:
//   SERVER  — offers RD (0x1111) and RC (0x2222) to the NAD
//   CLIENT  — forwards allowed calls to SafetyUC (Diag 0x3333, Ctrl 0x4444)
//
// Security:
//   The ReferenceMonitor checks EVERY inbound message before forwarding.
//   A message is forwarded only when:
//     1. The OMacFooter is present
//     2. The CMAC tag is authentic
//     3. The automaton allows the call in the current state
//
// Usage:
//   ./app_up <path/to/tcu_rd_rc_policy.json>
//
// vsomeip config (set via env var):
//   VSOMEIP_CONFIGURATION=examples/config/vsomeip-appup.json
//

#include "reference_monitor.hpp"
#include "crypto.hpp"
#include "footer.hpp"

#include <vsomeip/vsomeip.hpp>

#include <array>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// SOME/IP identifiers
// ---------------------------------------------------------------------------
// Services this app offers (NAD calls these)
constexpr vsomeip::service_t  RD_SERVICE    = 0x1111;
constexpr vsomeip::service_t  RC_SERVICE    = 0x2222;
// Services this app consumes (forwards to SafetyUC)
constexpr vsomeip::service_t  DIAG_SERVICE  = 0x3333;
constexpr vsomeip::service_t  CTRL_SERVICE  = 0x4444;

constexpr vsomeip::instance_t INSTANCE      = 0x0001;
constexpr vsomeip::method_t   METHOD_INVOKE = 0x0001;

static const std::array<uint8_t, 16> DEMO_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ---------------------------------------------------------------------------
// AppUP application
// ---------------------------------------------------------------------------
class AppUP {
public:
    explicit AppUP(const std::string& policy_path)
        : monitor_(policy_path)
        , app_(vsomeip::runtime::get()->create_application("app_up"))
        , diag_available_(false)
        , ctrl_available_(false)
    {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[AppUP] vsomeip init failed\n";
            return false;
        }

        // --- Server side: offer RD and RC services to NAD -------------------
        app_->register_message_handler(RD_SERVICE, INSTANCE, METHOD_INVOKE,
            [this](const std::shared_ptr<vsomeip::message>& msg) {
                on_nad_call(msg, "NAD::4G", "AppuP::RD", "invoke_RD",
                            DIAG_SERVICE, "AppuP::RD", "SafetyuC::Diag", "invoke_Diag");
            });

        app_->register_message_handler(RC_SERVICE, INSTANCE, METHOD_INVOKE,
            [this](const std::shared_ptr<vsomeip::message>& msg) {
                on_nad_call(msg, "NAD::4G", "AppuP::RC", "invoke_RC",
                            CTRL_SERVICE, "AppuP::RC", "SafetyuC::Ctrl", "invoke_Ctrl");
            });

        app_->offer_service(RD_SERVICE, INSTANCE);
        app_->offer_service(RC_SERVICE, INSTANCE);

        // --- Client side: request SafetyUC services -------------------------
        app_->register_availability_handler(DIAG_SERVICE, INSTANCE,
            [this](vsomeip::service_t, vsomeip::instance_t, bool avail) {
                std::lock_guard<std::mutex> lk(avail_mutex_);
                diag_available_ = avail;
                avail_cv_.notify_all();
                std::cout << "[AppUP] SafetyuC::Diag " << (avail ? "available" : "gone") << "\n";
            });

        app_->register_availability_handler(CTRL_SERVICE, INSTANCE,
            [this](vsomeip::service_t, vsomeip::instance_t, bool avail) {
                std::lock_guard<std::mutex> lk(avail_mutex_);
                ctrl_available_ = avail;
                avail_cv_.notify_all();
                std::cout << "[AppUP] SafetyuC::Ctrl " << (avail ? "available" : "gone") << "\n";
            });

        app_->request_service(DIAG_SERVICE, INSTANCE);
        app_->request_service(CTRL_SERVICE, INSTANCE);

        std::cout << "[AppUP] Broker ready — awaiting NAD calls\n";
        return true;
    }

    void start() { app_->start(); }
    void stop()  {
        app_->stop_offer_service(RD_SERVICE, INSTANCE);
        app_->stop_offer_service(RC_SERVICE, INSTANCE);
        app_->release_service(DIAG_SERVICE, INSTANCE);
        app_->release_service(CTRL_SERVICE, INSTANCE);
        app_->stop();
    }

private:
    ReferenceMonitor monitor_;
    std::shared_ptr<vsomeip::application> app_;

    std::mutex              avail_mutex_;
    std::condition_variable avail_cv_;
    bool diag_available_;
    bool ctrl_available_;

    // -----------------------------------------------------------------------
    // on_nad_call — called when NAD sends a message to this broker.
    //
    // Checks:  footer present → MAC valid → automaton allows
    // If all pass, builds a new signed message and forwards to SafetyUC.
    // -----------------------------------------------------------------------
    void on_nad_call(const std::shared_ptr<vsomeip::message>& msg,
                     const std::string& from,    const std::string& to,
                     const std::string& method,
                     vsomeip::service_t fwd_service,
                     const std::string& fwd_from, const std::string& fwd_to,
                     const std::string& fwd_method)
    {
        auto pl = msg->get_payload();
        std::vector<uint8_t> buf(pl->get_data(), pl->get_data() + pl->get_length());

        std::cout << "[AppUP] Received call: " << from << " → " << to
                  << " : " << method << "\n";

        // Gate: reference monitor decides
        if (!monitor_.check(buf, from, to, method)) {
            std::cerr << "[AppUP] *** Call BLOCKED by monitor — dropping ***\n";
            return;
        }

        // Wait for downstream service to be available (up to 2 s)
        {
            std::unique_lock<std::mutex> lk(avail_mutex_);
            bool& avail = (fwd_service == DIAG_SERVICE) ? diag_available_ : ctrl_available_;
            avail_cv_.wait_for(lk, std::chrono::seconds(2), [&]{ return avail; });
            if (!avail) {
                std::cerr << "[AppUP] Downstream service unavailable — dropping\n";
                return;
            }
        }

        // Build forwarded message: extract application payload, re-sign as app_up
        auto app_payload = payload_without_footer(buf);

        OMacFooter fwd_footer;
        fwd_footer.domain_id = 0x0002;  // AppuP domain
        fwd_footer.method_id = (fwd_service == DIAG_SERVICE) ? 0x0003 : 0x0004;
        crypto::sign_message(app_payload.data(), app_payload.size(), fwd_footer);
        footer_append(app_payload, fwd_footer);

        auto fwd_msg = vsomeip::runtime::get()->create_request();
        fwd_msg->set_service(fwd_service);
        fwd_msg->set_instance(INSTANCE);
        fwd_msg->set_method(METHOD_INVOKE);

        auto fwd_pl = vsomeip::runtime::get()->create_payload();
        fwd_pl->set_data(app_payload);
        fwd_msg->set_payload(fwd_pl);

        app_->send(fwd_msg);
        std::cout << "[AppUP] Forwarded: " << fwd_from << " → " << fwd_to
                  << " : " << fwd_method << "\n";
    }
};

// ---------------------------------------------------------------------------
static std::shared_ptr<AppUP> g_app;
static void on_signal(int) { if (g_app) g_app->stop(); }

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <policy.json>\n";
        return 1;
    }

    crypto::set_key(DEMO_KEY);

    g_app = std::make_shared<AppUP>(argv[1]);
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    if (!g_app->init()) return 1;
    g_app->start();
    return 0;
}
