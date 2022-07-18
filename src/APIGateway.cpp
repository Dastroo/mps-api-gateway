//
// Created by dawid on 01.04.2022.
//

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <log_helper/Log.h>

#include <mps_utils/Filesystem.h>

#include <my_utils/Bit.h>
#include <my_utils/Time.h>

#include <nlohmann/json.hpp>

#include "../include/APIGateway.h"
#include "../include/AuthenticationAPI.h"
#include "../include/FaucetAPI.h"
#include "../include/RpcError.h"
#include "../include/Security.h"
#include "../include/WalletMgrAPI.h"

#include <hash_map>


static const char *TAG = "APIGateway";

std::string ip_;
uint16_t port_;

std::array<std::string, 8> basic_header_keys;

std::unordered_map<std::string, std::bitset<32>> targets;// TODO: compare performance with std::map

enum flags : uint32_t {
    ///direct authenticationAPI target
    AUTH = 0,// TODO: check how bit operation work with 0

    // ACCOUNT TYPES
    ///registered account
    BASIC = 1 << 0,
    ///verified account (with email and phone nr)
    VERIFIED = 1 << 1,
    ///payed or test account with extra privileges
    VIP = 1 << 2,

    // TRAITS
    ///verified email
    EMAIL = 1 << 3,
    ///verified phone number
    PHONE_NR = 1 << 4,
    ///crypto address set
    XNO = 1 << 5
};

void APIGateway::init() {
#ifdef BUILD_DEBUG
    Log::init("\n");
#else
    Log::init(mps::SvrDir::var().append("logs/api-gateway/log"));
#endif
    AuthenticationAPI::init();
    FaucetAPI::init();
    WalletMgrAPI::init();

    basic_header_keys = {"Accept-Encoding", "Connection",
                         "Content-Length", "Content-Type",
                         "Host", "REMOTE_ADDR",
                         "REMOTE_PORT", "User-Agent"};
    std::sort(basic_header_keys.begin(), basic_header_keys.end());

    //  READ SERVER PARAMETERS FROM CONFIG FILE
    std::ifstream is(mps::filesystem::config());
    if (!is)
        throw std::invalid_argument(mps::filesystem::config() + " did not open correctly. may not exist?");

    nlohmann::json config = nlohmann::json::parse(is);
    if (!config.contains("ip"))
        throw std::invalid_argument("\"ip\" in: " + mps::filesystem::config() + " missing.");
    else if (!config.contains("port"))
        throw std::invalid_argument("\"port\" in: " + mps::filesystem::config() + " missing.");

    ip_ = config["ip"].get<std::string>();
    port_ = config["port"].get<uint32_t>();

    //  LOG SERVER PARAMETERS
    Log::i(TAG, "run", "ip: " + ip_ + " port: " + std::to_string(port_) + '\n');
}

void logger(const httplib::Request &req, const httplib::Response &res) {
    if (req.body.empty()) {
        std::stringstream ss;
        for (const auto &header: req.headers)
            if (!std::binary_search(basic_header_keys.begin(), basic_header_keys.end(), header.first))
                ss << header.first << ":" << header.second << "|";
        Log::i(TAG, req.path, "[" + req.remote_addr + "] req: " + ss.str());
    } else
        Log::i(TAG, req.path, "[" + req.remote_addr + "] req: " + req.body);

    if (res.body.empty())
        Log::w(TAG, req.path, "[" + req.remote_addr + "] res: empty");
    else
        Log::i(TAG, req.path, "[" + req.remote_addr + "] res: " + res.body);
}

httplib::Server::HandlerResponse pre_routing_handler(const httplib::Request &req, httplib::Response &res) {
    if (req.target == "/ping") {
        res.set_content(R"({"status": "ok"})", "application/json");
        return httplib::Server::HandlerResponse::Handled;
    }

    if (!security::verify(req)) {
        AuthenticationAPI::ban_ip(req, res, security::ban_duration);
        return httplib::Server::HandlerResponse::Handled;
    }

    if (std::bitset<32> flags = targets.at(req.target);
        mutl::bit::any((uint32_t) flags.to_ulong(), BASIC | VERIFIED) &&
        !AuthenticationAPI::auth_user(req, res, (uint32_t) flags.to_ulong()))
        return httplib::Server::HandlerResponse::Handled;

    return httplib::Server::HandlerResponse::Unhandled;
}

void exception_handler(const httplib::Request &req, httplib::Response &res, std::exception &e) {
    Log::e(TAG, req.path, "[" + req.remote_addr + "] " + e.what());
    const std::string &msg = [](std::exception &e) -> std::string {
        switch (rpce::code(e.what())) {
            case rpce::connection:
                return "Connection refused";
            case rpce::custom:
                return "Client error";
            case rpce::unknown:
                return "Unknown error";
            default:
                return "Server error";
        }
    }(e);
    // {{ & }} is escaping the '{' | '}' because in ftm "{}" is used to mark where the variable is inserted
    res.set_content(fmt::format(R"({{"status": {}, "msg": {}}})", 1, msg),
                    "application/json");
}

void error_handler(const httplib::Request &req, httplib::Response &res) {
    // {{ & }} is escaping the '{' | '}' because in ftm "{}" is used to mark where the variable is inserted
    res.set_content(fmt::format(R"({{"status": {}, "msg": {}}})", res.status, "Server has run into problems."),
                    "application/json");
}

void unhandled_targets_handler(const httplib::Request &req, httplib::Response &res) {
    AuthenticationAPI::ban_ip(req, res, security::ban_duration);
    res.set_content(R"("status": "you got banned for trying to exploit this api")",
                    "application/json");
}

void APIGateway::run() {
    // INIT SSL SERVER
    static httplib::SSLServer api(
            mps::filesystem::cert().c_str(),
            mps::filesystem::key().c_str());

    // CHECK FOR ERROR
    if (!api.is_valid()) {
        Log::e(TAG, "listener failed to initialize ssl unknown");
        throw std::invalid_argument(
                "wrong or nonexistent certs were given\n" +
                mps::filesystem::cert() + "\n" +
                mps::filesystem::key());
    }

    // MAIN INTERFACE
    api.Post(targets.emplace("/sign_up", AUTH).first->first, AuthenticationAPI::sign_up);
    api.Post(targets.emplace("/email/sign_in", AUTH).first->first, AuthenticationAPI::email::sign_in);
    api.Post(targets.emplace("/phone_nr/sign_in", AUTH).first->first, AuthenticationAPI::phone_nr::sign_in);

    api.Get(targets.emplace("/cointap/home", BASIC).first->first, FaucetAPI::home);
    api.Get(targets.emplace("/cointap/claim", BASIC).first->first, FaucetAPI::claim);

    api.Get(targets.emplace("/cointap/balance", BASIC).first->first, WalletMgrAPI::balance);
    api.Get(targets.emplace("/cointap/withdraw", BASIC | XNO).first->first, WalletMgrAPI::withdraw);
    api.Post(targets.emplace("/cointap/set_address", BASIC).first->first, WalletMgrAPI::set_address);
    api.Get(targets.emplace("/cointap/verify_address", BASIC).first->first, WalletMgrAPI::verify_address);

    // BAN ALL TRAFFIC OUTSIDE OF THE HANDLED TARGETS
    api.Post(R"(/(.*))", unhandled_targets_handler);
    api.Get(R"(/(.*))", unhandled_targets_handler);
    api.Options(R"(/(.*))", unhandled_targets_handler);
    api.Delete(R"(/(.*))", unhandled_targets_handler);
    api.Patch(R"(/(.*))", unhandled_targets_handler);
    api.Put(R"(/(.*))", unhandled_targets_handler);

    // SERVER FUNCTIONS
    api.set_logger(logger);
    api.set_pre_routing_handler(pre_routing_handler);
    api.set_exception_handler(exception_handler);
    api.set_error_handler(error_handler);

    api.set_read_timeout(5, 0); // 5 seconds
    api.set_write_timeout(5, 0);// 5 seconds

    //  SET A WAY TO GRACEFULLY STOP THIS PROCESS
    std::signal(SIGTERM, [](int signum) {
        api.stop();
        Log::release();

        exit(signum);
    });

    //  START SERVER
    api.listen(ip_.c_str(), port_);
}