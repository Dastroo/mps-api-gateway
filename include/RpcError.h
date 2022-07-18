//
// Created by dawid on 16.07.22.
//

#pragma once

#include <string>

/// rpc error
namespace rpce {
    constexpr const uint32_t unknown = 0;
    constexpr const uint32_t connection = 1;
    constexpr const uint32_t custom = 2;

    const char* get(const char *what);
    uint32_t code(const std::string &what);
}// namespace rpce
