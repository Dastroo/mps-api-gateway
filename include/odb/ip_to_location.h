// file      : hello/ip_to_location.hxx
// copyright : not copyrighted - public domain

#pragma once

#include <string>
#include <cstddef> // std::size_t

#include <odb/core.hxx>

#pragma db object
class ip_to_location {
    friend class odb::access;

    ip_to_location() {}

    #pragma db id
    unsigned int from_;
    unsigned int to_;
    std::string iso_code_;
    std::string name_;

public:
    ip_to_location(unsigned int from,
                   unsigned int to,
                   const std::string &iso_code,
                   const std::string &name) :
            from_(from), to_(to), iso_code_(iso_code), name_(name) {};

    unsigned int from() { return from_; }

    unsigned int to() { return to_; }

    std::string iso_code() { return iso_code_; };

    std::string name() { return name_; };
};