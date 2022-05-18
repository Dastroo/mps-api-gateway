//
// Created by dawid on 03.04.2022.
//

#include <fstream>
#include <utility>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/eax.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

#ifdef REDHAT

#include <json/value.h>
#include <json/reader.h>
#include <json/writer.h>

#endif
#ifdef DEBIAN
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/writer.h>
#endif

#include <odb/pgsql/database.hxx>
#include <odb/database.hxx>
#include <odb/transaction.hxx>

#include <mps_utils/SvrDir.h>

#include <log_helper/Log.h>
#include <my_utils/Time.h>

#include "user.h"
#include "user_odb.h"
#include "device.h"
#include "device_odb.h"
#include "ip.h"
#include "ip_odb.h"
#include "ip_to_location.h"
#include "ip_to_location_odb.h"
#include "../include/Ip.h"
#include "../include/ResponseError.h"
#include "../include/UserAuthAPI.h"


UserAuthAPI::UserAuthAPI(const Json::Value &params,
                         const std::string &iphub_api_key,
                         std::string encryption_key) :
        enc_dec_key(std::move(encryption_key)),
        ipHub(iphub_api_key) {
    const std::string &database = params["db_name"].asString();
    const std::string &password = params["db_password"].asString();

    int argc = 8;
    char *argv[8] = {
            (char *) "--host", (char *) "localhost",
            (char *) "--user", (char *) "mps-api-gateway",
            (char *) "--password", (char *) password.c_str(),
            (char *) "--database", (char *) database.c_str()
    };

    db = std::unique_ptr<odb::database>(new odb::pgsql::database(argc, argv));
}

bool UserAuthAPI::authenticate(httplib::Response &res,
                               const std::string &path,
                               uint64_t timestamp,
                               uint32_t id,
                               const std::string &token,
                               const std::string &ip_address,
                               flags type) const {
    typedef odb::query<user> query;

    auto u = db->query_one<user>(query::id == id && query::token == token);
    if (!u) {
        Json::Value contents;
        contents["error"] = NOT_REGISTERED;
        contents["timestamp"] = (Json::UInt64) timestamp;
        respond(res, contents, path);
        return false;
    } else if (u->type() < type) {
        Json::Value contents;
        contents["error"] = ACCOUNT_TYPE;
        contents["timestamp"] = (Json::UInt64) timestamp;
        respond(res, contents, path);
        return false;
    } else if (banned_u(*u, timestamp)) {
        Json::Value contents;
        contents["error"] = BANNED;
        contents["timestamp"] = (Json::UInt64) u->ban_expires();
        respond(res, contents, path);
        return false;
    }

    auto i(db->query_one<ip>(odb::query<ip>::address == ip_address));
    if (banned_i(*i, timestamp)) {
        Json::Value contents;
        contents["error"] = BANNED;
        contents["timestamp"] = (Json::UInt64) u->ban_expires();
        respond(res, contents, path);
        return false;
    }

    return true;
}

void
UserAuthAPI::sign_in(httplib::Response &res,
                     const std::string &android_id,
                     const std::string &pseudo_id,
                     const std::string &ip_address) const {

    const std::string &path = "/sign_in";
    uint64_t timestamp = mutl::time::now<mutl::time::sec>();

    //  CHECK IF DEVICE IS BANNED
    auto d(db->query_one<device>(odb::query<device>::android_id == android_id));
    if (d && (d->expires() > timestamp || d->expires() == 1)) {
        Json::Value content;
        content["error"] = BANNED;
        content["timestamp"] = (Json::UInt64) d->expires();
        respond(res, content, path);
        return;
    }

    // CHECK HOW MANY ACCOUNTS ON THE SAME IP IN PAST 5min WERE CREATED
    uint32_t n_accounts = 0;
    auto users = db->query<user>(odb::query<user>::timestamp >= timestamp - 300);
    for (const auto &u: users) {
        auto i(db->query_one<ip>(odb::query<ip>::client_id == u.id()));
        if (i->address() == ip_address)
            n_accounts++;
    }

    // BAN IF IS MULTI ACCOUNTING
    if (n_accounts > 3) {
        ban_device(android_id, timestamp, multi_accounting_ban);

        Json::Value content;
        content["error"] = BANNED;
        content["timestamp"] = (Json::UInt64) timestamp + multi_accounting_ban;
        respond(res, content, path);
        return;
    }

    //  GET IP ISO CODE
    std::string country = get_country_iso_code(ip_address);

    user u(timestamp, FAUCET, pseudo_id, crypto::UUID(), timestamp + token_lifetime_s);
    d.reset(new device(android_id, timestamp + device_registration_cooldown));

    odb::transaction t;

    uint64_t id = db->persist(u);
    ip i(id, ip_address, country, timestamp);
    db->persist(i);
    db->persist(d);

    t.commit();

    Json::Value content;
    content["error"] = SUCCESS;
    content["timestamp"] = (Json::UInt64) timestamp;
    content["id"] = (Json::UInt64) id;
    content["token"] = u.token();
    content["token_expires"] = (Json::UInt64) u.token_expires();
    respond(res, content, path);
}

void
UserAuthAPI::login(httplib::Response &res,
                   uint64_t timestamp,
                   uint32_t id,
                   const std::string &token,
                   const std::string &ip_address) const {
    typedef odb::query<user> query;
    const std::string &path = "/login";

    auto u(db->query_one<user>(query::id == id));

    u->token(crypto::UUID());
    u->token_expires(timestamp + token_lifetime_s);
    odb::transaction t(db->begin());
    db->update(u);
    t.commit();

    Json::Value content;
    content["error"] = SUCCESS;
    content["timestamp"] = (Json::UInt64) timestamp;
    content["token"] = u->token();
    content["token_expires"] = (Json::UInt64) u->token_expires();
    respond(res, content, path);
}

/*void UserAuthAPI::upgrade(httplib::Response &res,
                          uint64_t timestamp,
                          const std::string &ip_address) const {
    const std::string &path = "/upgrade";

    std::string country = get_country_iso_code(ip_address);
    if (country == "US" || country == "FR" || country == "UK" ||
        country == "JP" || country == "DE" || country == "IT" ||
        country == "CA") {
        if (!check_ip(ip_address, timestamp, country)) {
            //  TODO: process the warning in app
            Json::Value content;
            content["error"] = SUCCESS;
            content["timestamp"] = (Json::UInt64) timestamp;
            content["warning"] = vpn_warn;
            respond(res, content, path);
        }
    }
}*/

/// @return 1(true) if ip belongs to vpn provider
bool UserAuthAPI::check_ip(const std::string &ip_address, uint64_t timestamp, std::string &country) const {
    typedef odb::query<ip> query;

    uint32_t two_weeks = 1209600;
    auto i(db->query_one<ip>(
            query::address == ip_address &&
            query::vpn == true &&
            query::timestamp >= timestamp - two_weeks));
    if (i) {
        if (!i->country().empty() && i->country() != country)
            country = i->country();

        return true;
    }

    Json::Value res;
    Json::Reader().parse(ipHub.get(ip_address), res);
    std::string iso_code = res["countryCode"].asString();

    if (country != iso_code)
        country = iso_code;

    return res["block"] == 1;
}

void UserAuthAPI::respond(httplib::Response &res, const Json::Value &content, const std::string &endpoint) {
    std::string response = Json::FastWriter().write(content);
    res.set_content(response, "application/json");
    response.pop_back(); // to prevent newline char
    Log::i(TAG, endpoint, response);
}

std::string UserAuthAPI::get_country_iso_code(const std::string &ip_address) const {
    typedef odb::query<ip_to_location> query;
    uint64_t ip_int = Ip::toInt(ip_address);
    auto i(db->query_one<ip_to_location>(query::from < ip_int && query::to > ip_int));
    std::string iso_code = i->iso_code();
    return iso_code.empty() ? "US" : iso_code;
}

void UserAuthAPI::ban_device(const std::string &android_id, uint64_t timestamp, uint64_t for_how_long) const {
    auto d(db->query_one<device>(odb::query<device>::android_id == android_id));

    odb::transaction t(db->begin());

    if (d) {
        // EXTEND EXISTING BAN
        d->expires(int((timestamp + for_how_long) / 86400) * 86400);
        db->update(d);
    } else {
        // BAN DEVICE
        d.reset(new class device(android_id, int((timestamp + for_how_long) / 86400) * 86400));
        db->persist(d);
    }

    t.commit();
}

uint64_t UserAuthAPI::ban_ip(const std::string &ip_address, uint64_t timestamp, uint64_t for_how_long) const {
    auto i(db->query_one<ip>(odb::query<ip>::address == ip_address && odb::query<ip>::client_id == 0));

    odb::transaction t(db->begin());
    uint64_t ban_ends = timestamp + for_how_long;
    if (i) {
        i->ban_expires(ban_ends);
        db->update(i);
    } else {
        i.reset(new ip(0, ip_address, "", timestamp, ban_ends));
        db->persist(i);
    }

    t.commit();

    return ban_ends;
}

void UserAuthAPI::ban_user(uint64_t id, uint64_t timestamp, uint64_t for_how_long) const {
    auto u(db->query_one<user>(odb::query<user>::id == id));
    if (u) {
        odb::transaction t(db->begin());
        u->ban_expires(timestamp + for_how_long);
        db->update(u);
        t.commit();
    }
}

bool UserAuthAPI::banned_d(const std::string &android_id, uint64_t timestamp) const {
    typedef odb::query<device> query;
    auto d(db->query_one<device>(query::android_id == android_id));
    if (d)
        // 1 means permanently banned
        return d->expires() == 1 || d->expires() >= timestamp;

    return false;
}

bool UserAuthAPI::banned_i(const std::string &ip_address, uint64_t timestamp) const {
    typedef odb::query<ip> query;
    auto i(db->query_one<ip>(query::address == ip_address));
    if (i)
        // 1 means permanently banned
        return i->ban_expires() == 1 || i->ban_expires() >= timestamp;

    return false;
}

bool UserAuthAPI::banned_i(const ip &i, uint64_t timestamp) const {
    // 1 means permanently banned
    return i.ban_expires() == 1 || i.ban_expires() >= timestamp;
}

bool UserAuthAPI::banned_u(uint64_t id, uint64_t timestamp) const {
    typedef odb::query<user> query;
    auto u(db->query_one<user>(query::id == id));
    if (u)
        // 1 means permanently banned
        return u->ban_expires() == 1 || u->ban_expires() >= timestamp;

    return false;
}

bool UserAuthAPI::banned_u(const user &u, uint64_t timestamp) const {
    // 1 means permanently banned
    return u.ban_expires() == 1 || u.ban_expires() >= timestamp;
}
