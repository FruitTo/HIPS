#ifndef RULES_H
#define RULES_H 

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>

using namespace std;

struct Rules
{
    int sid;
    string actions;
    string protocol;
    string srcAddress;
    int srcPort;
    string dstAddress;
    int dstPort;
};

void read_rule(string path)
{
    // vector<Rules> rules;
    vector<string> lines;
    string line;
    ifstream file(path);

    if (!file.is_open())
    {
        cout << "Failed to open file." << endl;
    }

    while (getline(file, line))
    {
        lines.push_back(line);
    }

    regex rule_regex(R"((alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+any\s+any\s+->\s+any\s+(\d+)\s+\(.*?msg:\"([^\"]+)\";.*?sid:(\d+);.*?content:\"([^\"]+)\";.*?classtype:([^\s;]+);)");

    for (auto &line : lines)
    {
        cout << line << endl << endl;
        // smatch match;                   // Store result
        // if (regex_search(line, match, rule_regex))
        // {
        //     cout << "Action: " << match[1] << endl;
        //     cout << "Protocol: " << match[2] << endl;
        //     cout << "Dst Port: " << match[3] << endl;
        //     cout << "Msg: " << match[4] << endl;
        //     cout << "SID: " << match[5] << endl;
        //     cout << "Content: " << match[6] << endl;
        //     cout << "Classtype: " << match[7] << endl;
        // }
        // else
        // {
        //     cout << "❌ No match found!" << endl;
        // }
    }
}

#endif
