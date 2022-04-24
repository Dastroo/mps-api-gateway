//
// Created by dawid on 01.04.2022.
//

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib.h>
#include <log_helper/Log.h>
#include <mps_utils/SvrDir.h>
#include <mps_utils/NotificationsAPI.h>

#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <jsoncpp/json/reader.h>

#include "../include/ResponseError.h"
#include "../include/Accounts.h"
#include "../include/Account.h"
#include "../include/APIGateway.h"

void APIGateway::run() {
    Log::init(mps::SvrDir::var().append("logs/api-gateway/log"));
    DBHelper::set_default_path(mps::SvrDir::var().append("database.db3"));
    Log::i(TAG, DBHelper().get_db_full_path());

    std::string cert_dir = mps::SvrDir::usr();
    std::string cert_path = cert_dir + "root_ca.pem";
    std::string cert_key_path = cert_dir + "root_ca.key";
    static httplib::SSLServer api(cert_path.c_str(), cert_key_path.c_str());
    if (!api.is_valid()) {
        Log::e(TAG, "listener failed to initialize ssl server");
        throw std::invalid_argument("wrong or nonexistent certs were given\n" + cert_path + "\n" + cert_key_path);
    }

    Accounts accounts;
    mps::NotificationsAPI notificationsAPI;

    api.Post("/sign_in", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        std::string android_id = value["android_id"].asString();
        Account account(android_id, req.remote_addr);

        //  CREATE ACCOUNT
        Json::Value jor;
        error sign_err = accounts.sign_in(account);
        if (sign_err == SUCCESS) {
            jor["error"] = false; // false means no error
            jor["id"] = account.id;
        } else if (sign_err == REGISTERED) {
            jor["error"] = true; // true means error
            jor["error_code"] = sign_err;
            jor["id"] = account.id;
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = sign_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    api.Post("/login", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string android_id = value["android_id"].asString();
        Account account(android_id, id, req.remote_addr);

        Json::Value jor;
        error login_err = accounts.login(account);
        if (login_err == SUCCESS) {
            jor["error"] = false; // false means no error
            jor["token"] = account.token;
            jor["expiration_date"] = account.expiration_date;
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = login_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    api.Post("/sign_out", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            notificationsAPI.services_off(account.id);
            accounts.sign_out(account);
            jor["error"] = false; // false means no error
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });


    api.Post("/logout", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            accounts.logout(account);
            jor["error"] = false; // false means no error
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    //  TODO: needs testings
    api.Post("/update_firebase_token", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        //  UPDATE TOKEN ON AUTHENTICATION SUCCESS
        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            std::string firebase_token = value["firebase_token"].asString();
            notificationsAPI.update_firebase_token(account.id, firebase_token);
            jor["error"] = false; // false means no error
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    api.Post("/services", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        //  FETCH SERVICES ON AUTHENTICATION SUCCESS
        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            if (!reader.parse(notificationsAPI.services(account.id), jor["services"], false))
                Log::e(TAG, req.path, reader.getFormattedErrorMessages());
            jor["error"] = false; // false means no error
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = Json::FastWriter().write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    api.Post("/service_on", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        //  ADD ACCOUNT TO SERVICE ON AUTHENTICATION SUCCESS
        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            std::string service = value["service"].asString();
            std::string firebase_token = value["firebase_token"].asString();
            notificationsAPI.service_on(service, account.id, firebase_token);
            jor["error"] = false;
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = (Json::FastWriter()).write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

    api.Post("/service_off", [&](const httplib::Request &req, httplib::Response &res) {
        Log::i(TAG, req.path, req.body);

        //  PARSE JSON
        Json::Value value;
        Json::Reader reader;
        if (!reader.parse(req.body, value, false))
            Log::e(TAG, req.path, reader.getFormattedErrorMessages());

        //  COLLECT REQUEST DATA
        int id = value["id"].asInt();
        std::string token = value["token"].asString();
        Account account(id, token, req.remote_addr);

        //  REMOVE ACCOUNT FROM SERVICE ON AUTHENTICATION SUCCESS
        Json::Value jor;
        error auth_err = accounts.authenticate(account);
        if (auth_err == SUCCESS) {
            std::string service = value["service"].asString();
            notificationsAPI.service_off(service, account.id);
            jor["error"] = false; // false means no error
        } else {
            jor["error"] = true; // true means error
            jor["error_code"] = auth_err;
        }

        std::string response = (Json::FastWriter()).write(jor);
        res.set_content(response, "application/json");
        response.pop_back(); // to prevent newline char
        Log::i(TAG, req.path, response);
    });

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

    //  READ IP FROM JSON FILE
    Json::Value value;
    std::ifstream is(mps::SvrDir::usr().append("config.json"));
    Json::Reader().parse(is, value, false);
    std::string ip = value["ip"].asString();
    Log::i(TAG, "run", "ip: " + ip);

    api.listen(ip.c_str(), 1618);
}