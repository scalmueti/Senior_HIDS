#include "clean_devices.h"
#include <iostream>
#include <regex>

std::string cleanDeviceName(const std::string &rawName) {
    std::regex npfPattern(R"(\\Device\\NPF_\{?([0-9A-Fa-f\-]+)\}?)"); 
    std::smatch match;

    if (std::regex_match(rawName, match, npfPattern) && match.size() > 1) {
        return match[1];  
    }
    return rawName;
}
