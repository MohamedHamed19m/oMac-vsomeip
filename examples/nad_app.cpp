//
// nad_app.cpp — NAD: SOME/IP client demo driver
//
// Simulates the Network Access Device (LTE modem + GPS) from the oMac paper.
// Runs a scripted demo sequence:
//
//   [1] F1  LEGIT  — invoke_RD   (NAD::4G → AppuP::RD)   → ALLOWED
//   [2] F2  LEGIT  — invoke_RC   (NAD::4G → AppuP::RC)   → ALLOWED
//   [3] F3  ATTACK — invoke_RD then immediately invoke_RC again out of sequence
//   [4] F4  ATTACK — NAD::GPS tries invoke_RD              → BLOCKED at app_up
//   [5] F5  ATTACK — message with no footer                → BLOCKED
//
// The reference monitor in app_up decides ALLOW / BLOCK.
// This app only sends — the monitor output appears in the app_up terminal.
//
// Usage:
//   ./nad_app
//
// vsomeip config (set via env var):
//   VSOMEIP_CONFIGURATION=examples/config/vsomeip-nad.json
//
// Paper-faithful: uses SecuredPayload (subclass of vsomeip::payload) which
// overrides serialize() to transparently append the OMacFooter on the wire.
//

#include "crypto.hpp"
#include "secured_payload.hpp"

#include <vsomeip/vsomeip.hpp>

#include <array>
#include <atomic>
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
// SOME/IP identifiers — must match those in app_up.cpp
// ---------------------------------------------------------------------------
constexpr vsomeip::service_t  RD_SERVICE    = 0x1111;
constexpr vsomeip::service_t  RC_SERVICE    = 0x2222;
constexpr vsomeip::instance_t INSTANCE      = 0x0001;
constexpr vsomeip::method_t   METHOD_INVOKE = 0x0001;

static const std::array<uint8_t, 16> DEMO_KEY = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ---------------------------------------------------------------------------
// Helper: build a SecuredPayload (paper-faithful — subclass of vsomeip::payload)
// The footer is automatically computed and appended inside serialize() when
// vsomeip sends the message on the wire. No manual footer_append() needed.
// ---------------------------------------------------------------------------
static std::shared_ptr<vsomeip::payload>
make_payload(const std::string& app_data, uint16_t domain_id, uint16_t method_id)
{
    std::vector<uint8_t> buf(app_data.begin(), app_data.end());
    return omac::SecuredPayload::make_outbound(buf, domain_id, method_id);
}

// ---------------------------------------------------------------------------
// Helper: build a standard (unsecured) payload — no footer, for attack demo.
// ---------------------------------------------------------------------------
static std::shared_ptr<vsomeip::payload>
make_unsigned_payload(const std::string& app_data)
{
    std::vector<uint8_t> buf(app_data.begin(), app_data.end());
    auto pl = vsomeip::runtime::get()->create_payload();
    pl->set_data(buf);
    return pl;
}

// ---------------------------------------------------------------------------
// NAD application
// ---------------------------------------------------------------------------
class NAD {
public:
    NAD() : app_(vsomeip::runtime::get()->create_application("nad_app"))
          , rd_available_(false)
          , rc_available_(false)
          , running_(true)
    {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[NAD] vsomeip init failed\n";
            return false;
        }

        app_->register_availability_handler(RD_SERVICE, INSTANCE,
            [this](vsomeip::service_t, vsomeip::instance_t, bool avail) {
                std::lock_guard<std::mutex> lk(avail_mutex_);
                rd_available_ = avail;
                avail_cv_.notify_all();
                std::cout << "[NAD] AppuP::RD service " << (avail ? "available" : "gone") << "\n";
            });

        app_->register_availability_handler(RC_SERVICE, INSTANCE,
            [this](vsomeip::service_t, vsomeip::instance_t, bool avail) {
                std::lock_guard<std::mutex> lk(avail_mutex_);
                rc_available_ = avail;
                avail_cv_.notify_all();
                std::cout << "[NAD] AppuP::RC service " << (avail ? "available" : "gone") << "\n";
            });

        app_->request_service(RD_SERVICE, INSTANCE);
        app_->request_service(RC_SERVICE, INSTANCE);

        // Run the demo sequence in a background thread so app_->start() can block
        demo_thread_ = std::thread([this]{ run_demo(); });

        return true;
    }

    void start() { app_->start(); }
    void stop()  {
        running_ = false;
        avail_cv_.notify_all();
        if (demo_thread_.joinable()) demo_thread_.join();
        app_->release_service(RD_SERVICE, INSTANCE);
        app_->release_service(RC_SERVICE, INSTANCE);
        app_->stop();
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    std::mutex              avail_mutex_;
    std::condition_variable avail_cv_;
    bool rd_available_;
    bool rc_available_;
    std::atomic<bool>       running_;
    std::thread             demo_thread_;

    // Wait until a given service is available, with timeout
    bool wait_available(bool& flag, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk(avail_mutex_);
        return avail_cv_.wait_for(lk, timeout, [&]{ return flag || !running_; }) && flag;
    }

    void send_to(vsomeip::service_t service,
                 std::shared_ptr<vsomeip::payload> pl,
                 const std::string& label)
    {
        auto msg = vsomeip::runtime::get()->create_request(false);
        msg->set_service(service);
        msg->set_instance(INSTANCE);
        msg->set_method(METHOD_INVOKE);
        msg->set_payload(pl);
        app_->send(msg);
        std::cout << "[NAD] Sent: " << label << "\n";
    }

    void pause(int ms = 1000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // -----------------------------------------------------------------------
    // run_demo — the scripted sequence
    // -----------------------------------------------------------------------
    void run_demo() {
        // Wait for app_up to become available
        std::cout << "[NAD] Waiting for broker services...\n";
        if (!wait_available(rd_available_, std::chrono::seconds(10))) {
            std::cerr << "[NAD] Timeout waiting for AppuP::RD — is app_up running?\n";
            return;
        }

        pause(500);
        std::cout << "\n========================================\n";
        std::cout << "  oMac-vsomeip Demo — Flow Sequence\n";
        std::cout << "========================================\n\n";

        // ---- [1] F1: Legitimate Remote Diagnostic --------------------------
        std::cout << ">>> [1] LEGIT F1: NAD::4G → AppuP::RD (invoke_RD)\n";
        send_to(RD_SERVICE,
                make_payload("DIAG_SESSION_DATA", 0x0001, 0x0001),
                "invoke_RD (legit)");
        pause();

        // ---- [2] Flow 2 (legit): Remote Control ----------------------------
        std::cout << ">>> [2] LEGIT F2: NAD::4G → AppuP::RC (invoke_RC)\n";
        send_to(RC_SERVICE,
                make_payload("CTRL_SESSION_DATA", 0x0001, 0x0002),
                "invoke_RC (legit)");
        pause();

        // ---- [3] Attack: RC out of sequence (RC→Ctrl without prior RD) ----
        std::cout << ">>> [3] ATTACK: invoke_RC twice in a row (out of sequence)\n";
        send_to(RC_SERVICE,
                make_payload("ATTACK_RC_REPEAT", 0x0001, 0x0002),
                "invoke_RC (attack — out of sequence)");
        pause();
        // In state nad_called_rc, sending another RC is unknown → blocked
        send_to(RC_SERVICE,
                make_payload("ATTACK_RC_DOUBLE", 0x0001, 0x0002),
                "invoke_RC again (attack)");
        pause();

        // ---- [4] Attack F4: GPS interface tries to invoke RD ---------------
        std::cout << ">>> [4] ATTACK F4: NAD::GPS → AppuP::RD (unauthorized sender)\n";
        // We encode domain_id=0x0005 to hint GPS origin,
        // but the FROM component name in app_up is what the monitor checks.
        // In a real system the monitor would resolve the sender ID from the
        // vsomeip routing table. Here app_up logs the block clearly.
        send_to(RD_SERVICE,
                make_payload("GPS_SPOOF_PAYLOAD", 0x0005, 0x0001),
                "invoke_RD as GPS (blocked by app_up)");
        pause();

        // ---- [5] Attack: no footer at all ----------------------------------
        std::cout << ">>> [5] ATTACK: message with NO footer\n";
        send_to(RD_SERVICE,
                make_unsigned_payload("RAW_UNPROTECTED"),
                "invoke_RD without footer (blocked immediately)");
        pause();

        std::cout << "\n========================================\n";
        std::cout << "  Demo complete — check app_up output\n";
        std::cout << "========================================\n";

        // Graceful shutdown
        app_->stop();
    }
};

// ---------------------------------------------------------------------------
static std::shared_ptr<NAD> g_app;
static void on_signal(int) { if (g_app) g_app->stop(); }

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;  // nad_app doesn't need the policy directly

    crypto::set_key(DEMO_KEY);

    g_app = std::make_shared<NAD>();
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    if (!g_app->init()) return 1;
    g_app->start();
    g_app->stop();
    return 0;
}



