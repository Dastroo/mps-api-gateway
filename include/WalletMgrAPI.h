//
// Created by dawid on 04.07.22.
//

#pragma once

#include <httplib.h>

class WalletMgrAPI {
    inline static const char *TAG = "WalletMgrAPI";

    inline static const char *host = "127.0.0.1";
    inline static const uint16_t port = 1618;

    WalletMgrAPI() = default;

public:
    static void init();

    static void ping(const httplib::Request &req, httplib::Response &res);
    static void balance(const httplib::Request &req, httplib::Response &res);
    static void withdraw(const httplib::Request &req, httplib::Response &res);
    static void verify_address(const httplib::Request &req, httplib::Response &res);
    static void set_address(const httplib::Request &req, httplib::Response &res);
};
