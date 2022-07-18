//
// Created by dawid on 05.07.22.
//

#pragma once

#include <httplib.h>

class FaucetAPI {
    inline static const char *TAG = "FaucetAPI";

    inline static const char *host = "127.0.0.1";
    inline static const uint16_t port = 1618;

    FaucetAPI() = default;

public:
    static void init();

    static void home(const httplib::Request &req, httplib::Response &res);
    static void claim(const httplib::Request &req, httplib::Response &res);
};
