//
// Created by dawid on 02.05.22.
//

#pragma once

#include <string>
#include <utility>
#include <stdexcept>
#include <array>

struct Ip {
    /// returns 0 on fail
    static uint64_t toInt(const std::string& ip) {
        int i = 0;
        std::array<std::string, 4> octetsStr;
        for (auto &c: ip) {
            if (c == '.') {
                i++;
                continue;
            }
            octetsStr[i].append(1, c);
        }

        if (i != 3)
            return 0;

        int octets[4];
        try {
            octets[0] = stoi(octetsStr[0]);
            octets[1] = stoi(octetsStr[1]);
            octets[2] = stoi(octetsStr[2]);
            octets[3] = stoi(octetsStr[3]);
        } catch ( std::exception& e ) {
            return 0;
        }

        return (octets[0] * 16777216l) + (octets[1] * 65536l) + (octets[2] * 256l) + (octets[3]);
    }

    static std::string toStr(uint64_t ip) {
        if ( ip > 4294967295l ) {
            throw std::runtime_error(std::string("Invalid IP: ") + std::to_string(ip));
        }

        int octets[4];
        octets[0] = ip / 16777216l;
        ip = ip - octets[0] * 16777216l;
        octets[1] = ip / 65536l;
        ip = ip - octets[1] * 65536l;
        octets[2] = ip / 256l;
        ip = ip - octets[2] * 256l;
        octets[3] = ip;

        std::string convIp;
        convIp.append(std::to_string(octets[0])).append(".")
                .append(std::to_string(octets[1])).append(".")
                .append(std::to_string(octets[2])).append(".")
                .append(std::to_string(octets[3]));
        return convIp;
    }
};
