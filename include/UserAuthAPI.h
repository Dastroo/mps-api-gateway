//
// Created by dawid on 07.01.2022.
//

#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib.h>

#include <odb/database.hxx>

#include <my_utils/StringUtils.h>

#include "ip.h"
#include "user.h"

#include "Crypto.h"
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
    enum flags {
        FAUCET = 1 << 0,
        OFFERWALL = 1 << 1,
        EMAIL_VER = 1 << 2,
        TEL_NR_VER = 1 << 3,

    };

    UserAuthAPI(const Json::Value &params, const std::string &iphub_api_key, std::string encryption_key);

    ~UserAuthAPI() = default;

    template<typename ...Args>
    inline bool verify(httplib::Response &res,
                       const std::string &path,
                       const std::string &ip_address,
                       const std::string &hash,
                       Args...args) const {
        if (crypto::sha256Hash(mutl::concatenate(args...)) == hash)
            return true;

        uint64_t timestamp = mutl::time::now<mutl::time::sec>();
        uint64_t ban_ends = ban_ip(ip_address, timestamp, api_exploit_ban);

        Json::Value contents;
        contents["error"] = BANNED;
        contents["timestamp"] = (Json::UInt64) ban_ends;
        respond(res, contents, path);
        return false;
    }

    [[nodiscard]]
    bool authenticate(httplib::Response &res,
                      const std::string &path,
                      uint64_t timestamp,
                      uint32_t id,
                      const std::string &token,
                      const std::string &ip_address,
                      flags type) const;

    void sign_in(httplib::Response &res,
                 const std::string &android_id,
                 const std::string &pseudo_id,
                 const std::string &ip_address) const;

    void login(httplib::Response &res,
               uint64_t timestamp,
               uint32_t id,
               const std::string &token,
               const std::string &ip_address) const;

    /*void upgrade(httplib::Response &res,
                 uint64_t timestamp,
                 const std::string &ip_address) const;*/

private:
    [[nodiscard]]
    bool check_ip(const std::string &ip_address, uint64_t timestamp, std::string &country) const;

    static void respond(httplib::Response &res, const Json::Value &content, const std::string &endpoint);

    void ban_device(const std::string &android_id, uint64_t timestamp, uint64_t for_how_long) const;

    [[nodiscard]]
    uint64_t ban_ip(const std::string &ip_address, uint64_t timestamp, uint64_t for_how_long) const;

    void ban_user(uint64_t id, uint64_t timestamp, uint64_t for_how_long) const;

    [[nodiscard]]
    bool banned_d(const std::string &android_id, uint64_t timestamp) const;

    [[nodiscard]]
    bool banned_i(const std::string &ip_address, uint64_t timestamp) const;

    [[nodiscard]]
    bool banned_i(const ip &i, uint64_t timestamp) const;

    [[nodiscard]]
    bool banned_u(uint64_t id, uint64_t timestamp) const;

    [[nodiscard]]
    bool banned_u(const user &u, uint64_t timestamp) const;

    [[nodiscard]]
    std::string get_country_iso_code(const std::string &ip_address) const;
};
