//
// Created by dawid on 19.02.2022.
//

#pragma once


enum error {
    ///action completed successfully
    SUCCESS = 0,
    ///account already exists
    REGISTERED = 1,
    ///account send different token than in database
    TOKEN = 2,
    ///account credentials not valid
    NOT_VALID = 3,
    ///account does not registered
    NOT_REGISTERED = 4,
    ///account needs to login before using service
    NOT_LOGGED = 5,
    ANDROID_ID = 6,
    FIREBASE_TOKEN = 7
};
