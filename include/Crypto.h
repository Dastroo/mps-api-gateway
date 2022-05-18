//
// Created by dawid on 5/17/22.
//

#pragma once

#include <string>

namespace crypto {
    std::string UUID();

    std::string sha256Hash(const std::string &s);

    std::string encrypt(const std::string &str, std::string &iv_out, const std::string &key_);

    std::string decrypt(const std::string &cipher, const std::string &iv_str, const std::string &key_);
};