//
// Created by dawid on 07.01.2022.
//

#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib.h>

#include <odb/database.hxx>

#include <my_utils/StringUtils.h>

#include "ResponseError.h"
#include "IPHubAPI.h"

class user;

//  TODO: user email verification
//  TODO: user phone verification
class UserAuthAPI {
    inline static const char *TAG = "AccountMgr";

    const std::string enc_dec_key;

    const uint32_t token_lifetime_s = 604800; // in seconds
    const uint32_t device_registration_cooldown = 2592000;

    const uint32_t vpn_ban = 2592000;
    const uint32_t multi_accounting_ban = 2592000;
    const uint32_t api_exploit_ban = 2592000;

    const std::string vpn_warn = "Please turn of your vpn service while using this app";

    const IPHubAPI ipHub;
    std::unique_ptr<odb::database> db;

public:
    enum user_type {
        FAUCET,
        OFFERWALL
    };

    UserAuthAPI(const Json::Value &params, const std::string &iphub_api_key, std::string encryption_key);

    ~UserAuthAPI() = default;

    template<typename ...Args>
    inline bool verify(httplib::Response &res,
                       const std::string &path,
                       const std::string &ip,
                       const std::string &hash,
                       Args...args) const {
        if (sha256Hash(mutl::concatenate(args...)) != hash) {
            uint64_t timestamp = seconds_science_epoch();
            ban_ip(ip, timestamp, api_exploit_ban);

            Json::Value contents;
            contents["error"] = BANNED;
            contents["timestamp"] = (Json::UInt64) timestamp + api_exploit_ban;
            respond(res, contents, path);
            return false;
        }

        return true;
    }

    [[nodiscard]]
    bool authenticate(uint32_t id,
                      const std::string &token,
                      user_type type) const;

    void sign_in(httplib::Response &res,
                 const std::string &android_id,
                 const std::string &pseudo_id,
                 const std::string &ip) const;

    void login(httplib::Response &res,
               uint32_t id,
               const std::string &token,
               const std::string &ip_address) const;

    void upgrade(httplib::Response &res,
                 const std::string &ip_address) const;

private:
    [[nodiscard]]
    bool check_ip(const std::string &ip_address, uint64_t timestamp, std::string &country) const;

    static void respond(httplib::Response &res, const Json::Value &content, const std::string &endpoint);

    void ban_device(const std::string &android_id, uint64_t timestamp, uint64_t for_how_long) const;

    void ban_ip(const std::string &ip_address, uint64_t timestamp, uint64_t for_how_long) const;

    void ban_user(uint64_t id, uint64_t timestamp, uint64_t for_how_long) const;

    [[nodiscard]]
    std::string get_country_iso_code(const std::string &ip) const;

    static unsigned long seconds_science_epoch();

    static std::string guid();

    static std::string sha256Hash(const std::string &s);

    std::string encrypt(const std::string &s, std::string &iv_out) const;

    std::string decrypt(const std::string &cipher, const std::string &iv_str) const;
};
