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
    auto rules = SnortRuleParser::parseRulesFromFile("./rule/snort3-community.rules");
    if (rules.empty())
    {
        cout << "rules not found!" << endl;
        return 1;
    }

    if (rules.count("tcp") > 0 && !rules["tcp"].empty())
    {
        cout << *rules["tcp"][0].action << endl;
    }

    if (rules.count("tcp") > 0 && !rules["tcp"].empty())
    {
        cout << static_cast<int>(rules["tcp"][0].option.general.classtype) << endl;
    }

    if (rules.count("tcp") > 0 && rules["tcp"].size() > 76)
    {
        if (rules["tcp"][76].option.nonpayload.ip_proto)
        {
            cout << static_cast<int>(get<uint8_t>(rules["tcp"][76].option.nonpayload.ip_proto->protocol));
        }
    }

    if (rules.count("tcp") > 0 && rules["tcp"].size() > 59)
    {
        if (rules["tcp"][59].option.nonpayload.flow &&
            rules["tcp"][59].option.nonpayload.flow->connection_state)
        {
            auto state = *rules["tcp"][59].option.nonpayload.flow->connection_state;
            cout << "Connection State: " << static_cast<int>(state) << endl;
        }
    }

    return 0;
}