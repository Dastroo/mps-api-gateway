//
// Created by dawid on 07.01.2022.
//

#pragma once


#include <string>

#include <odb/core.hxx>
#include <odb/nullable.hxx>


//  TODO: add device language
#pragma db object

class user {
    user() {}

    friend class odb::access;

#pragma db id auto
    unsigned long id_;

    unsigned long timestamp_;

    unsigned char type_;

    std::string pseudo_id_;

    std::string crypto_address_;

    std::string email_;

    std::string tel_nr_;

    std::string iv_;

    /// "password"
    std::string token_;

    /// in seconds from epoch
    unsigned long token_expires_;

    bool suspicious_;

    /// 0 - not banned, 1 - banned indefinitely, ban_expires>1 - banned until ban_expires in seconds
    unsigned long ban_expires_;

public:
    user(unsigned long timestamp,
         unsigned char type,
         const std::string &pseudo_id,
         const std::string &crypto_address,
         const std::string &email,
         const std::string &tel_nr,
         const std::string &iv,
         const std::string &token,
         unsigned long token_expires,
         bool suspicious = false,
         unsigned long ban_expires = 0) :
            timestamp_(timestamp),
            type_(type),
            pseudo_id_(pseudo_id),
            crypto_address_(crypto_address),
            email_(email),
            tel_nr_(tel_nr),
            iv_(iv),
            token_(token),
            token_expires_(token_expires),
            suspicious_(suspicious),
            ban_expires_(ban_expires) {};

    user(unsigned long timestamp,
         unsigned char type,
         const std::string &pseudo_id,
         const std::string &token,
         unsigned long token_expires,
         bool suspicious = false,
         unsigned long ban_expires = 0) :
            timestamp_(timestamp),
            type_(type),
            pseudo_id_(pseudo_id),
            token_(token),
            token_expires_(token_expires),
            suspicious_(suspicious),
            ban_expires_(ban_expires) {};

    unsigned long
    id() const { return id_; }

    unsigned long
    timestamp() const { return timestamp_; }

    unsigned char
    type() const { return type_; }

    const std::string &
    pseudo_id() const { return pseudo_id_; }

    const std::string &
    crypto_address() const { return crypto_address_; }

    const std::string &
    email() { return email_; }

    const std::string &
    tel_nr() { return tel_nr_; }

    const std::string &
    iv() const { return iv_; }

    const std::string &
    token() const { return token_; }

    unsigned long
    token_expires() const { return token_expires_; }

    bool
    suspicious() const { return suspicious_; }

    unsigned long
    ban_expires() { return ban_expires_; }

    void
    type(unsigned char type) { type_ = type; }

    void
    timestamp(unsigned long timestamp) { timestamp_ = timestamp; }

    void
    crypto_address(const std::string &address) { crypto_address_ = address; }

    void
    email(const std::string &email) { email_ = email; }

    void
    tel_nr(const std::string &tel_nr) { tel_nr_ = tel_nr; }

    void
    iv(const std::string &iv) { iv_ = iv; }

    void
    token(const std::string &token) { token_ = token; }

    void
    token_expires(unsigned long time) { token_expires_ = time; }

    void
    suspicious(bool suspicious) { suspicious_ = suspicious; }

    void
    ban_expires(unsigned long time) { ban_expires_ = time; }
};
