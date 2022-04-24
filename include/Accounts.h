//
// Created by dawid on 07.01.2022.
//

#pragma once

#include <db_helper/DBHelper.h>


struct Account;
//  TODO: account email verification
//  TODO: account phone verification
class Accounts {
    inline static const char *TAG = "Accounts";

    const std::string table = "Accounts";
    const std::string col_id = "id";
    const std::string col_token = "token";
    const std::string col_expiration_date = "expiration_date";
    const std::string col_android_id = "android_id";
    const std::string col_ip_address = "ip_address";

    const unsigned int token_lifetime_s = 604800; // in seconds

    DBHelper db_helper;

public:
    Accounts();

    ~Accounts() = default;

    /**
     * @brief adds account to database and sets account.id to its id in table accounts
     * @param account.android_id
     * @return
     */
    error sign_in(Account &account);

    void sign_out(Account &account);

    /**
     * @brief login is for token
     * @param account.id
     * @param account.android_id
     */
    error login(Account &account);

    /**
     * @brief deletes the token and expiration date of an account from db
     * @param account.id
     */
    void logout(Account &account);

    /**
     *
     * @param account.id
     * @param account.token
     * @return
     */
    error authenticate(Account &account);

private:
    /// by android_id
    void db_get_account_id(Account &account);

    /// by id
    void set_token(Account &account);

    /// by id
    void set_expiration_date(Account &account);

    /// by id
    void set_android_id(Account &account);

    /// by id
    void set_ip_address(Account &account);

    void db_get_account(Account &account);

    void db_add_account(Account &account);

    /// updates all account info even the uninitialized
    void db_update_account(Account &account);

    /// updates all initialized account info
    void db_update_account_i(Account &account);

    void db_remove_account(Account &account);

    static bool is_valid_android_id(Account &account);

    void set_new_token(Account &account) const;

    static unsigned int seconds_science_epoch();

    static std::string guid();

    static std::string sha256Hash(const std::string &aString);
};
