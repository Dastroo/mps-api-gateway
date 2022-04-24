//
// Created by dawid on 03.04.2022.
//

#include <chrono>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <log_helper/Log.h>

#include "../include/Account.h"
#include "../include/ResponseError.h"
#include "../include/Accounts.h"

Accounts::Accounts() {
    if (db_helper.table_exists(table)) {
        if (db_helper.table_empty(table))
            db_helper.drop(table);
        else
            return;
    }

    using type = DBHelper::type;
    db_helper.create(table,
                     col_id, type::INTEGER, type::PRIMARY_KEY, type::AUTO_INCREMENT,
                     col_token, type::TEXT,
                     col_expiration_date, type::INTEGER,
                     col_android_id, type::TEXT,
                     col_ip_address, type::TEXT);
}

/**
 * @brief adds account to database and sets account.id to its id in table accounts
 * @param account.android_id
 * @return
 */
error Accounts::sign_in(Account &account) {
    if (!is_valid_android_id(account))
        return ANDROID_ID;

    if (db_helper.exists(table, col_android_id, account.android_id)) {
        db_get_account_id(account);
        return REGISTERED;
    }

    db_add_account(account);
    db_get_account_id(account);

    return SUCCESS;
}

void Accounts::sign_out(Account &account) {
    db_remove_account(account);
}

/**
 * @brief login is for token
 * @param account.id
 * @param account.android_id
 */
error Accounts::login(Account &account) {
    //  check if account at account.id exists
    if (!db_helper.exists(table, col_id, account.id))
        return NOT_REGISTERED;

    //  check if account.android_id matches that in row @id
    std::string android_id = db_helper.get(table, col_android_id, col_id, account.id).getString();
    if (account.android_id != android_id)
        return NOT_VALID;

    set_new_token(account);
    db_update_account_i(account);

    return SUCCESS;
}

/**
 * @brief deletes the token and expiration date of an account from db
 * @param account.id
 */
void Accounts::logout(Account &account) {
    db_get_account(account);
    account.token.clear();
    account.expiration_date = 0;
    db_update_account(account);
}

/**
 *
 * @param account.id
 * @param account.token
 * @return
 */
error Accounts::authenticate(Account &account) {
    //  check if account at account.id exists
    if (!db_helper.exists(table, col_id, account.id))
        return NOT_REGISTERED;

    //  check if account.token is not expired and if token exist in database
    set_expiration_date(account);
    std::string token = db_helper.get(table, col_token, col_id, account.id).getString();
    if (token.empty() || account.expiration_date <= seconds_science_epoch())
        return NOT_LOGGED;

    //  check if account.token matches that in db @row account.id
    if (account.token.size() != 44 || account.token != token)
        return TOKEN;

    return SUCCESS;
}

/// by android_id
void Accounts::db_get_account_id(Account &account) {
    account.id = db_helper.get(table, col_id, col_android_id, account.android_id).getInt();
}

/// by id
void Accounts::set_token(Account &account) {
    account.token = db_helper.get(table, col_token, col_id, account.id).getString();
}

/// by id
void Accounts::set_expiration_date(Account &account) {
    account.expiration_date = db_helper.get(table, col_expiration_date, col_id, account.id).getUInt();
}

/// by id
void Accounts::set_android_id(Account &account) {
    account.android_id = db_helper.get(table, col_android_id, col_id, account.id).getString();
}

/// by id
void Accounts::set_ip_address(Account &account) {
    account.ip_address = db_helper.get(table, col_ip_address, col_id, account.id).getString();
}

void Accounts::db_get_account(Account &account) {
    auto query = db_helper.select(table, std::make_tuple(col_id, "=", account.id));
    if (query->executeStep())
        account = {
                query->getColumn("id").getInt(),
                query->getColumn("token").getString(),
                query->getColumn("expiration_date").getUInt(),
                query->getColumn("android_id").getString(),
                query->getColumn("ip_address").getString()
        };
}

void Accounts::db_add_account(Account &account) {
    db_helper.insert(table,
                     col_token,
                     col_expiration_date,
                     col_android_id,
                     col_ip_address,
                     account.token,
                     account.expiration_date,
                     account.android_id,
                     account.ip_address);
}

/// updates all account info even the uninitialized
void Accounts::db_update_account(Account &account) {
    if (account.id == -1) {
        Log::w(TAG, "db_update_account", "account.id not set");
        return;
    }
    //                      WHERE
    db_helper.update(table, col_id, account.id,
            // SET
                     col_token,
                     account.token,
                     col_expiration_date,
                     account.expiration_date,
                     col_android_id,
                     account.android_id,
                     col_ip_address,
                     account.ip_address);
}

/// updates all initialized account info
void Accounts::db_update_account_i(Account &account) {
    if (account.id == -1) {
        Log::w(TAG, "db_update_account_i", "account.id not set");
        return;
    }

    if (!account.android_id.empty())
        db_helper.update(table, col_id, account.id,
                         col_android_id, account.android_id);

    if (!account.token.empty())
        db_helper.update(table, col_id, account.id,
                         col_token, account.token);

    if (!account.ip_address.empty())
        db_helper.update(table, col_id, account.id,
                         col_ip_address, account.ip_address);

    if (account.expiration_date != 0)
        db_helper.update(table, col_id, account.id,
                         col_expiration_date, account.expiration_date);
}

void Accounts::db_remove_account(Account &account) {
    if (account.id == -1) {
        Log::w(TAG, "db_remove_account", "account.id not set");
        return;
    }

    db_helper.dele(table, col_id, account.id);
}

bool Accounts::is_valid_android_id(Account &account) {
    if (account.android_id.empty()) {
        Log::w(TAG, "is_valid_android_id",
               "empty android_id: " +
               account.android_id);
        return false;
    }
    if (account.android_id.size() != 16) {
        Log::w(TAG, "is_valid_android_id",
               "size: " + std::to_string(account.android_id.size()) + " android_id: " + account.android_id);
        return false;
    }

    return true;
}

void Accounts::set_new_token(Account &account) const {
    std::string uid = guid();
    account.token = uid;

    unsigned int now = seconds_science_epoch();
    account.expiration_date = now + token_lifetime_s;
}

unsigned int Accounts::seconds_science_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string Accounts::guid() {
    using namespace std::chrono;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);

    unsigned long long now = duration_cast<nanoseconds>(
            system_clock::now().time_since_epoch()).count();

    std::string id = sha256Hash(std::to_string(now));

    return id;
}

std::string Accounts::sha256Hash(const std::string &aString) {
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(
            aString,
            true,
            new CryptoPP::HashFilter(
                    hash,
                    new CryptoPP::Base64Encoder(
                            new CryptoPP::StringSink(digest))));
    digest.pop_back();
    return digest;
}