//
// Created by dawid on 30.04.22.
//

#pragma once

#include <string>
#include <odb/core.hxx>

#pragma db object
class device {
    friend class odb::access;

    device() {}

    #pragma db id
    std::string android_id_;

    // time after which it can be deleted
    unsigned long expires_;

public:
    device(const std::string &android_id, unsigned long expires) :
            android_id_(android_id), expires_(expires) {};

    const std::string &
    android_id() const { return android_id_; }

    unsigned long
    expires() const { return expires_; }

    /// time after which it can be deleted
    void
    expires(unsigned long expires) { expires_ = expires; }
};
