#ifndef SNORT_RULE_H
#define SNORT_RULE_H

#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <variant>
#include <unordered_map>
#include <regex>
#include <fstream>
#include <sstream>
#include <optional>
#include <cstdint>

enum class ipFormat {
    static,
    subnet,
    any,
    variable
}

struct IP {
    switch (ipFormat){

    }
}

struct Rule {
    string action;
    string protocal;
    IP ip;
}



#endif