//
// Created by dawid on 02.05.22.
//

#pragma once

#include <string>
#include <odb/core.hxx>

#pragma db object

class ip {
    friend class odb::access;

    ip() {}

#pragma db id auto
    unsigned long id_;

    // join with user.id()
    unsigned long client_id_; // todo: change to user_id

    std::string address_;

    std::string country_;

    unsigned long timestamp_;

    bool vpn_;

    unsigned long ban_expires_;

public:
    ip(unsigned long client_id,
       const std::string &address,
       const std::string &country,
       unsigned long timestamp,
       bool vpn = false,
       unsigned long ban_expires = 0) :
            client_id_(client_id), address_(address), country_(country), timestamp_(timestamp), vpn_(vpn), ban_expires_(ban_expires) {}

    unsigned long
    id() const { return id_; }

    unsigned long
    client_id() const { return client_id_; }

    const std::string &
    address() const { return address_; }

    const std::string &
    country() const { return country_; }

    unsigned long
    timestamp() const { return timestamp_; }

    bool
    vpn() { return vpn_; }

    unsigned long
    ban_expires() const { return ban_expires_; }

    void
    timestamp(unsigned long timestamp) { timestamp_ = timestamp; }

    void
    vpn(bool vpn) { vpn_ = vpn; }

    void
    ban_expires(unsigned long ban_expires) { ban_expires_ = ban_expires; }
};