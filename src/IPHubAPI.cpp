//
// Created by dawid on 05.05.22.
//

#include <sstream>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <log_helper/Log.h>
#include "../include/IPHubAPI.h"


std::string IPHubAPI::get(const std::string &ip) const {
    try {
        curlpp::Easy request;
        //  -G url
        std::string url = "http://v2.api.iphub.info/ip/" + ip;
        request.setOpt<curlpp::options::Url>(url);

        //  -H headers
        std::list<std::string> headers;
        headers.emplace_back("X-Key: " + api_key_);
        headers.emplace_back("content-type: text/json");
        request.setOpt<curlpp::options::HttpHeader>(headers);

        request.setOpt<curlpp::options::ConnectTimeout>(connect_timeout);

        //  get result as string
        std::ostringstream os;
        request.setOpt<curlpp::options::WriteStream>(&os);

        request.perform();

        return os.str();
    } catch (curlpp::RuntimeError &e) {
        Log::e(TAG, "get", e.what());
        return {};
    } catch (curlpp::LogicError &e) {
        Log::e(TAG, "get", e.what());
        return {};
    }
}