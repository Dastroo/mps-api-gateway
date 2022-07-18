//
// Created by dawid on 08.07.22.
//

#pragma once

#include <httplib.h>
#include <mps_utils/Crypto.h>
#include <my_utils/StringUtils.h>

namespace security {
    /// api exploit ban duration
    const uint64_t ban_duration = 2629800000;

    template<typename... Args>
    [[nodiscard]] static std::string
    generateKey(const Args... strings) {
        std::string phrase = "dupa";

        std::string result = crypto::sha256(mutl::concatenate(strings...) + phrase);
        result = crypto::sha256(result.append(phrase));
        result = crypto::sha256(result.append(phrase));

        return result;
    }

    [[nodiscard]] bool
    verify(const httplib::Request &req);

}// namespace security
