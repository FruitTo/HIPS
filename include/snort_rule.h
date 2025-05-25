#ifndef SNORT_RULE_H
#define SNORT_RULE_H

#include <json/json.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>

inline Json::Value readRule()
{
    std::ifstream rule_file("snortparser/rules.json", std::ifstream::binary);
    Json::Value rules;
    // Rule Classify

    Json::CharReaderBuilder builder;
    std::string errs;
    Json::parseFromStream(builder, rule_file, &rules, &errs);
    return rules;
}

#endif
