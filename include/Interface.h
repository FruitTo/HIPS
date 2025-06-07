#ifndef INTERFACE_H
#define INTERFACE_H

#include <iostream>
#include <vector>
#include <string>
#include <tins/tins.h>
#include <sstream>

std::vector<std::string> getInterfaceName(){
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

std::string getIpInterface(std::string name){
    try {
        Tins::NetworkInterface iface(name);
        return iface.ipv4_address().to_string();
    }
    catch (const std::exception& error) {
        std::cerr << "Error getting IP for interface " << name 
                  << ": " << error.what() << std::endl;
        return "";  // Return empty string on error
    }
}

#endif
