#ifndef OPTION_DETECTION_H 
#define OPTION_DETECTION_H 

#include "flow.h"
#include "packet.h"
#include "snort_rule.h"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

void payloadDetection(){

}

void nonePayloadeDetection(){

}

bool optionDetection(PacketInfo &packet, std::map<std::string, std::vector<Rule>> &rules, const NetworkConfig &conf) {
    return false;
}

#endif