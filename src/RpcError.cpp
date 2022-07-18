//
// Created by dawid on 16.07.22.
//

#include "../include/RpcError.h"
#include <array>
#include <cstring>

std::array<const char *, 2> error_msg = {
        "rpc::rpc_error during call",
        "Connection refused"
};

const char *rpce::get(const char *what) {
    if (std::strcmp(what, error_msg[0]) == 0) return "0";
    else if (std::strcmp(what, error_msg[1]) == 0)
        return "1";
    else
        return "2";
}

uint32_t rpce::code(const std::string &what) {
    return std::stoi(what.substr(0, 1));
}