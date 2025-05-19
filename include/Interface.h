#ifndef INTERFACE_H
#define INTERFACE_H

#include <iostream>
#include <vector>
#include <string>
#include <tins/tins.h>
#include <sstream>

std::vector<std::string> getInterface(){
    std::vector<std::string> interface;
    std::vector<Tins::NetworkInterface> iface = Tins::NetworkInterface::all();

    std::cout << "Your interface :";

    for(const auto& i : iface){
        std::cout << " " + i.name();
    }
    std::cout << std::endl << "Select your interface : ";
    std::string input;
    std::string word;
    std::getline(std::cin, input);
    std::istringstream iss(input);
    while(iss >> word){
        interface.push_back(word);
    }
    return interface;
}

#endif
