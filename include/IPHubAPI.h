//
// Created by dawid on 05.05.22.
//

#pragma once

#include <string>
#include <utility>

/// https://iphub.info/api TODO: handle HTTP 429 (Too Many Requests) status code
class IPHubAPI {
    const std::string TAG = "IPHubAPI";

    const std::string api_key_;
    const uint32_t connect_timeout = 3; // in seconds

public:
    IPHubAPI() = default;

    explicit IPHubAPI(std::string api_key) : api_key_(std::move(api_key)) {};

    [[nodiscard]] std::string get(const std::string &ip) const;
};
