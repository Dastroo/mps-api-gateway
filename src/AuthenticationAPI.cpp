//
// Created by dawid on 03.04.2022.
//

#include "../include/AuthenticationAPI.h"
#include "../include/RpcError.h"

#include <rpc/client.h>

#include <log_helper/Log.h>


static const char *TAG = "AuthenticationAPI";

static const char *host_ = "127.0.0.1";
static const uint16_t port_ = 1618;

void AuthenticationAPI::init() {
}

void AuthenticationAPI::ban_ip(const httplib::Request &req,
                               httplib::Response &res,
                               uint64_t duration) {
    rpc::client c(host_, port_);
    try {
        res.set_content(c.call("ban_ip",
                               req.remote_addr,
                               duration)
                                .as<std::string>(),
                        "application/json");
    } catch (std::runtime_error &e) {
        const std::string &nr = rpce::get(e.what());
        // error_nr api::function: error description
        throw std::runtime_error(nr + " AuthenticationAPI::auth_new_user: " + e.what());
    }
}

bool AuthenticationAPI::auth_user(const httplib::Request &req,
                                  httplib::Response &res,
                                  uint32_t flags) {
    rpc::client c(host_, port_);
    try {
        const auto pair = c.call("auth_user",
                                 req.remote_addr,
                                 std::stoi(req.get_header_value("id")),// TODO: make sure that id is a integer !!!
                                 req.get_header_value("token"),
                                 flags)
                                  .as<std::pair<bool, std::string>>();
        if (!pair.first)
            res.set_content(pair.second, "application/json");
        return pair.first;
    } catch (std::runtime_error &e) {
        const std::string &nr = rpce::get(e.what());
        // error_nr api::function: error description
        throw std::runtime_error(nr + " AuthenticationAPI::auth_new_user: " + e.what());
    }
}

void AuthenticationAPI::sign_up(const httplib::Request &req,
                                httplib::Response &res) {
    rpc::client c(host_, port_);
    try {
        res.set_content(c.call("sign_up",
                               req.remote_addr,
                               req.get_header_value("android_id"),
                               req.get_header_value("pseudo_id"))
                                .as<std::string>(),
                        "application/json");
    } catch (std::runtime_error &e) {
        const std::string &nr = rpce::get(e.what());
        // error_nr api::function: error description
        throw std::runtime_error(nr + " AuthenticationAPI::auth_new_user: " + e.what());
    }
}

void AuthenticationAPI::email::sign_in(const httplib::Request &req,
                                       httplib::Response &res) {
    rpc::client c(host_, port_);
    try {
        res.set_content(c.call("/email/sign_in",
                               req.remote_addr,
                               req.get_header_value("email"),
                               req.get_header_value("android_id"),
                               req.get_header_value("pseudo_id"))
                                .as<std::string>(),
                        "application/json");
    } catch (std::runtime_error &e) {
        const std::string &nr = rpce::get(e.what());
        // error_nr api::function: error description
        throw std::runtime_error(nr + " AuthenticationAPI::auth_new_user: " + e.what());
    }
}

void AuthenticationAPI::phone_nr::sign_in(const httplib::Request &req,
                                          httplib::Response &res) {
    rpc::client c(host_, port_);
    try {
        res.set_content(c.call("/phone_nr/sign_in",
                               req.remote_addr,
                               req.get_header_value("phone_nr"),
                               req.get_header_value("android_id"),
                               req.get_header_value("pseudo_id"))
                                .as<std::string>(),
                        "application/json");
    } catch (std::runtime_error &e) {
        const std::string &nr = rpce::get(e.what());
        // error_nr api::function: error description
        throw std::runtime_error(nr + " AuthenticationAPI::auth_new_user: " + e.what());
    }
}