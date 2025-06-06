#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/snort_rule_parser.h"
#include "./include/snort_rule.h"
#include <string>
#include <iostream>
#include <vector>
#include <sstream>

using namespace std;

int main()
{
    vector<Rule> rules = SnortRuleParser::parseRulesFromFile("./rule/snort3-community.rules");
    if (rules.empty())
    {
        cout << "rules not found!" << endl;
        return 1;
    }
    // optional
    cout << *rules[0].action << endl;
    // enum class
    cout << static_cast<int>(rules[0].option.general.classtype) << endl;
    // varian (uint8_t have to use static_cast)
    cout << static_cast<int>(get<uint8_t>(rules[76].option.nonpayload.ip_proto->protocol));

    if (rules[59].option.nonpayload.flow &&
        rules[59].option.nonpayload.flow->connection_state)
    {

        auto state = *rules[59].option.nonpayload.flow->connection_state;
        cout << "Connection State: " << static_cast<int>(state) << endl;
    }

    return 0;
}