//
// Created by dawid on 01.04.2022.
//

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <httplib.h>
#include <log_helper/Log.h>
#include <mps_utils/SvrDir.h>
#include <mps_utils/NotificationsAPI.h>

#include <my_utils/Time.h>

#ifdef REDHAT

#include <json/value.h>
#include <json/writer.h>
#include <json/reader.h>

#elifdef DEBIAN
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <jsoncpp/json/reader.h>
#endif

#include "../include/APIGateway.h"
#include "include/UserAuthAPI.h"

void APIGateway::run() {
#ifdef BUILD_DEBUG
    Log::init();
#else
    Log::init(mps::SvrDir::var().append("logs/api-gateway/log"));
#endif

    std::string cert_dir = mps::SvrDir::usr();
    std::string cert_path = cert_dir + "root_ca.pem";
    std::string cert_key_path = cert_dir + "root_ca.key";
    static httplib::SSLServer api(cert_path.c_str(), cert_key_path.c_str());
    if (!api.is_valid()) {
        Log::e(TAG, "listener failed to initialize ssl server");
        throw std::invalid_argument("wrong or nonexistent certs were given\n" + cert_path + "\n" + cert_key_path);
    }

    //  READ PARAMETERS FROM JSON FILE
    Json::Value value;
    std::ifstream is(mps::SvrDir::usr().append("config.json"));
    Json::Reader().parse(is, value, false);
    std::string ip = value["ip"].asString();
    Log::i(TAG, "run", "ip: " + ip);

    const UserAuthAPI authAPI(value, value["iphub_api_key"].asString(), value["enc_dec_key"].asString());

    api.Post("/sign_in", [&authAPI](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        std::string android_id = value["android_id"].asString();
        std::string pseudo_id = value["pseudo_id"].asString();
        std::string hash = value["hash"].asString();
        std::string ip = req.remote_addr;

        if (!authAPI.verify(res, req.path, hash, android_id, pseudo_id))
            return;

        authAPI.sign_in(res, android_id, pseudo_id, ip);
    });

    api.Post("/login", [&authAPI](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        uint64_t id = value["id"].asUInt64();
        std::string token = value["token"].asString();
        std::string hash = value["hash"].asString();
        std::string ip_addr = req.remote_addr;
        uint64_t timestamp = mutl::time::now<mutl::time::seconds>();

        if (!authAPI.verify(res, req.path, ip_addr, hash, id, token) ||
            !authAPI.authenticate(res, req.path, timestamp, id, token, ip_addr, UserAuthAPI::FAUCET))
            return;

        authAPI.login(res, timestamp, id, token, ip_addr);
    });

    /*api.Post("/upgrade", [&authAPI](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        uint64_t id = value["id"].asUInt64();
        std::string token = value["token"].asString();
        std::string hash = value["hash"].asString();
        std::string ip_addr = req.remote_addr;
        uint64_t timestamp = mutl::time::now<mutl::time::sec>();

        if (!authAPI.verify(res, req.path, ip_addr, hash, id, token) ||
            !authAPI.authenticate(res, req.path, timestamp, id, token, ip_addr, UserAuthAPI::FAUCET))
            return;

        //  TODO: upgrade system
        authAPI.upgrade(res, timestamp, ip_addr);
    });*/

    api.Get("/ping", [&](const httplib::Request &req, httplib::Response &res) {
        res.set_content("{status: ok}", "application/json");
        Log::i(TAG, req.path, "ip: " + req.remote_addr);
    });

    //  SET A WAY TO GRACEFULLY STOP THIS PROCESS
    std::signal(SIGTERM, [](int signum) {
        api.stop();
        Log::release();

        exit(signum);
    });

    api.listen(ip.c_str(), 1618);
}