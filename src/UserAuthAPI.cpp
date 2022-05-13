//
// Created by dawid on 03.04.2022.
//

#include <chrono>
#include <fstream>
#include <utility>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/eax.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

#include <jsoncpp/json/value.h>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/writer.h>

#include <odb/pgsql/database.hxx>
#include <odb/database.hxx>
#include <odb/transaction.hxx>

#include <mps_utils/SvrDir.h>

#include <log_helper/Log.h>

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

bool UserAuthAPI::authenticate(uint32_t id, const std::string &token, user_type type) const {
    typedef odb::query<user> query;
    return (bool) db->query_one<user>(query::id == id && query::token == token && query::type >= type);
}

void
UserAuthAPI::sign_in(httplib::Response &res,
                     const std::string &android_id,
                     const std::string &pseudo_id,
                     const std::string &ip_address) const {

    const std::string path = "/sign_in";
    uint64_t timestamp = seconds_science_epoch();

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

    user u(timestamp, FAUCET, pseudo_id, guid(), timestamp + token_lifetime_s);
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
                   uint32_t id,
                   const std::string &token,
                   const std::string &ip_address) const {
    typedef odb::query<user> query;

    const std::string path = "/login";
    uint64_t timestamp = seconds_science_epoch();

    auto u(db->query_one<user>(query::id == id && query::token == token));
    if (!u) {
        Json::Value content;
        content["error"] = NOT_REGISTERED;
        content["timestamp"] = (Json::UInt64) timestamp;
        respond(res, content, path);
        return;
    }

    u->token(guid());
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

void UserAuthAPI::upgrade(httplib::Response &res,
                          const std::string &ip_address) const {
    const std::string path = "/login";
    uint64_t timestamp = seconds_science_epoch();

    std::string country = get_country_iso_code(ip_address);
    if (country == "US" || country == "FR" || country == "UK" ||
        country == "JP" || country == "DE" || country == "IT" ||
        country == "CA") {
        if (!check_ip(ip_address, timestamp, country)) {
            // TODO: warn user that he needs to disable vpn
            Json::Value content;
            content["error"] = SUCCESS;
            content["timestamp"] = (Json::UInt64) timestamp;
            content["warning"] = "";
            respond(res, content, path);
        }
    }
}

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

std::string UserAuthAPI::get_country_iso_code(const std::string &ip) const {
    typedef odb::query<ip_to_location> query;
    uint64_t ip_int = Ip::toInt(ip);
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

void UserAuthAPI::ban_ip(const std::string &ip_address, uint64_t timestamp, uint64_t for_how_long) const {
    auto i(db->query_one<ip>(odb::query<ip>::address == ip_address && odb::query<ip>::client_id == 0));

    odb::transaction t(db->begin());

    if (i) {
        i->ban_expires(timestamp + for_how_long);
        db->update(i);
    } else {
        i.reset(new ip(0, ip_address, "", timestamp, timestamp + for_how_long));
        db->persist(i);
    }

    t.commit();
}

void UserAuthAPI::ban_user(uint64_t id, uint64_t timestamp, uint64_t for_how_long) const {
    auto i(db->query_one<user>(odb::query<user>::id == id));
    if (i) {
        odb::transaction t(db->begin());
        i->ban_expires(timestamp + for_how_long);
        db->update(i);
        t.commit();
    }
}

uint64_t UserAuthAPI::seconds_science_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string UserAuthAPI::guid() {
    using namespace std::chrono;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);

    unsigned long long now = duration_cast<nanoseconds>(
            system_clock::now().time_since_epoch()).count();

    std::string uid = sha256Hash(std::to_string(now));

    return uid;
}

std::string UserAuthAPI::sha256Hash(const std::string &aString) {
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(
            aString,
            true,
            new CryptoPP::HashFilter(
                    hash,
                    new CryptoPP::Base64Encoder(
                            new CryptoPP::StringSink(digest))));
    digest.pop_back();
    return digest;
}

std::string UserAuthAPI::encrypt(const std::string &s, std::string &iv_out) const {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    key.Assign((unsigned char *) enc_dec_key.c_str(), enc_dec_key.size());
    prng.GenerateBlock(iv, iv.size());

    iv_out = std::string(iv.begin(), iv.end());

    EAX<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    std::string cipher;
    StringSource ss(s, true,
                    new AuthenticatedEncryptionFilter(e,
                                                      new StringSink(cipher)
                    ) // AuthenticatedEncryptionFilter
    ); // StringSource

    return cipher;
}

std::string UserAuthAPI::decrypt(const std::string &cipher, const std::string &iv_str) const {
    using namespace CryptoPP;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    key.Assign((unsigned char *) enc_dec_key.c_str(), enc_dec_key.size());
    iv.Assign((unsigned char *) iv_str.c_str(), iv_str.size());

    std::string recovered;
    EAX<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    StringSource ss(cipher, true,
                    new AuthenticatedDecryptionFilter(d,
                                                      new StringSink(recovered)
                    ) // AuthenticatedDecryptionFilter
    ); // StringSource

    return recovered;
}
