//
// Created by dawid on 19.02.2022.
//

#pragma once


enum error {
    ///action completed successfully
    SUCCESS = 0,
    ///user account suspended
    BANNED = 1,
    ///user account already exists
    REGISTERED = 2,
    ///user account does not exist
    NOT_REGISTERED = 3,
};
