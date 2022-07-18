//
// Created by dawid on 07.01.2022.
//

#pragma once


#include <httplib.h>

//  TODO: user email verification
//  TODO: user phone verification
namespace AuthenticationAPI {

    void init();

    void ban_ip(const httplib::Request &req, httplib::Response &res, uint64_t duration);

    bool auth_user(const httplib::Request &req, httplib::Response &res, uint32_t flags);

    void sign_up(const httplib::Request &req, httplib::Response &res);

    namespace email {
        void sign_in(const httplib::Request &req, httplib::Response &res);
    }

    namespace phone_nr {
        void sign_in(const httplib::Request &req, httplib::Response &res);
    }

}// namespace AuthenticationAPI
