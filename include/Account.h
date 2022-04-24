//
// Created by dawid on 07.01.2022.
//

#pragma once


#include <string>
#include <utility>

struct Account {
    /// rowid from database, is -1 on default
    int id = -1;
    /// "password"
    std::string token;
    /// in seconds from epoch
    unsigned int expiration_date = 0;
    std::string android_id;
    std::string ip_address;

    Account(int id, std::string token, std::string ip_address) : id(id), token(std::move(token)),
                                                                 ip_address(std::move(ip_address)) {};

    Account(std::string android_id, int id, std::string ip_address) : id(id), android_id(std::move(android_id)),
                                                                 ip_address(std::move(ip_address)) {};

    Account(std::string android_id,
            std::string ip_address) :
            android_id(std::move(android_id)),
            ip_address(std::move(ip_address)) {};

    Account(int id,
            std::string token,
            unsigned long long expiration_date,
            std::string android_id,
            std::string ip_address) :
            id(id),
            token(std::move(token)),
            expiration_date(expiration_date),
            android_id(std::move(android_id)),
            ip_address(std::move(ip_address)) {};

    ~Account() = default;
};
