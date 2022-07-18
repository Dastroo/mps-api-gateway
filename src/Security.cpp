//
// Created by dawid on 08.07.22.
//

#include "../include/Security.h"



bool security::verify(const httplib::Request &req) {
    if (!req.has_header("key") || req.remote_addr.empty())
        return false;

    if (req.target == "/sign_up") {
        if (!req.has_header("android_id"))
            return false;
        if (!req.has_header("pseudo_id"))
            return false;

        const std::string &android_id = req.get_header_value("android_id");
        const std::string &pseudo_id = req.get_header_value("pseudo_id");
        const std::string &key = req.get_header_value("key");

        return generateKey(android_id, pseudo_id) == key;
    }

    if (!req.has_header("id"))
        return false;
    if (!req.has_header("token"))
        return false;

    const auto &id = req.get_header_value("id");
    const auto &token = req.get_header_value("token");
    const auto &key = req.get_header_value("key");

    return generateKey(id, token) == key;
}