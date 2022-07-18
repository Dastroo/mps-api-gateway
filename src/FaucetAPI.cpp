//
// Created by dawid on 05.07.22.
//

#include "../include/FaucetAPI.h"

#include <my_utils/Time.h>

void FaucetAPI::init() {
}

void FaucetAPI::home(const httplib::Request &req, httplib::Response &res) {
    /*nlohmann::json value = nlohmann::json::parse(req.body);
                 const uint32_t id = value["id"].get<uint32_t>();
                 const std::string &token = value["token"].get<std::string>();
                 const std::string &key = value["key"].get<std::string>();*/

    res.set_content(R"({"status": 0, "claim_amount": 1})", "application/json");
}
void FaucetAPI::claim(const httplib::Request &req, httplib::Response &res) {
    /*nlohmann::json value = nlohmann::json::parse(req.body);
                 const uint32_t id = value["id"].get<uint32_t>();
                 const std::string &token = value["token"].get<std::string>();
                 const std::string &key = value["key"].get<std::string>();*/

    std::string next_claim = std::to_string(mutl::time::now<mutl::time::milli>() + 15000) + "}";
    res.set_content(R"({"status": 0, "claim_reward": 1, "balance": 1, "next_claim": )" + next_claim, "application/json");
}
