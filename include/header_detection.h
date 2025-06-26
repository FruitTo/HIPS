#ifndef HEADER_DETECTION_H 
#define HEADER_DETECTION_H

#include "flow.h"
#include "packet.h"
#include "snort_rule.h"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

// Helper function สำหรับ resolve variables
std::string resolveVariable(const std::string& var, const NetworkConfig& conf) {
    if(var == "$HOME_NET" && conf.HOME_NET) {
        return *conf.HOME_NET;
    }
    else if(var == "$EXTERNAL_NET" && conf.EXTERNAL_NET) {
        return *conf.EXTERNAL_NET;
    }
    return var;
}

bool isInNetwork(const std::string &ip, const std::string &network) {
    if (network == "any") return true;
    
    // Handle negation (!192.168.1.0/24)
    if(network[0] == '!') {
        return !isInNetwork(ip, network.substr(1));
    }
    
    if (network.find('/') == std::string::npos) {
        return ip == network;
    }
    
    // Basic CIDR matching - for production should use proper IP library
    std::string network_base = network.substr(0, network.find('/'));
    return ip.find(network_base.substr(0, network_base.find_last_of('.'))) == 0;
}

bool isPortMatch(const std::string &rule_port, const std::string &packet_port) {
    if (rule_port == "any") return true;

    // Handle negation (!80)
    if (rule_port[0] == '!') {
        return rule_port.substr(1) != packet_port;
    }

    // Handle range (80:8080)
    if (rule_port.find(':') != std::string::npos) {
        std::stringstream ss(rule_port);
        std::string start_port, end_port;
        std::getline(ss, start_port, ':');
        std::getline(ss, end_port);

        int packet_port_num = std::stoi(packet_port);
        int start_num = std::stoi(start_port);
        int end_num = std::stoi(end_port);

        return packet_port_num >= start_num && packet_port_num <= end_num;
    }

    // Exact match
    return rule_port == packet_port;
}

bool isServiceEnabled(const Rule &rule, const NetworkConfig &conf) {
    if (!rule.option.general.service) return true;

    for (const auto &service : *rule.option.general.service) {
        if (service == "http") {
            if (!conf.HTTP_SERVERS || !*conf.HTTP_SERVERS) return false;
        } 
        else if (service == "smtp") {
            if (!conf.SMTP_SERVERS || !*conf.SMTP_SERVERS) return false;
        } 
        else if (service == "telnet") {
            if (!conf.TELNET_SERVERS || !*conf.TELNET_SERVERS) return false;
        } 
        else if (service == "sip") {
            if (!conf.SIP_SERVERS || !*conf.SIP_SERVERS) return false;
        } 
        else if (service == "sql" || service == "mysql" || service == "oracle") {
            if (!conf.SQL_SERVERS || !*conf.SQL_SERVERS) return false;
        }
    }

    return true;
}

bool checkAddressMatch(const Rule &rule, PacketInfo &packet, const NetworkConfig &conf) {
    if(!rule.direction || !rule.src_addr || !rule.dst_addr) return false;
    
    // Resolve variables to actual values
    std::string resolved_src = resolveVariable(*rule.src_addr, conf);
    std::string resolved_dst = resolveVariable(*rule.dst_addr, conf);
    
    if(*rule.direction == "->") {
        // Unidirectional: src -> dst
        return isInNetwork(packet.src_addr, resolved_src) && 
               isInNetwork(packet.dst_addr, resolved_dst);
    }
    else if(*rule.direction == "<>") {
        // Bidirectional: match both directions
        return (isInNetwork(packet.src_addr, resolved_src) && 
                isInNetwork(packet.dst_addr, resolved_dst)) ||
               (isInNetwork(packet.src_addr, resolved_dst) && 
                isInNetwork(packet.dst_addr, resolved_src));
    }
    
    return false;
}

bool checkPortMatch(const Rule &rule, PacketInfo &packet) {
    // Get packet ports based on protocol
    std::string packet_src_port, packet_dst_port;
    
    if (packet.protocol == "tcp" && packet.tcp) {
        packet_src_port = packet.tcp->sport;
        packet_dst_port = packet.tcp->dport;
    } 
    else if (packet.protocol == "udp" && packet.udp) {
        packet_src_port = packet.udp->sport;
        packet_dst_port = packet.udp->dport;
    } 
    else if (packet.protocol == "icmp") {
        // ICMP doesn't have ports
        return true;
    }
    else {
        // Unknown protocol with ports
        return false;
    }

    // Check source port
    if (rule.src_port && !isPortMatch(*rule.src_port, packet_src_port)) {
        return false;
    }

    // Check destination port
    if (rule.dst_port && !isPortMatch(*rule.dst_port, packet_dst_port)) {
        return false;
    }

    return true;
}

bool checkIPProtocol(const Rule &rule, PacketInfo &packet) {
    if(!rule.option.nonpayload.ip_proto) return true;
    
    const auto &ip_proto_opt = *rule.option.nonpayload.ip_proto;
    
    uint8_t target_proto;
    if (std::holds_alternative<uint8_t>(ip_proto_opt.protocol)) {
        target_proto = std::get<uint8_t>(ip_proto_opt.protocol);
    } else {
        std::string proto_str = std::get<std::string>(ip_proto_opt.protocol);
        if (proto_str == "icmp") target_proto = 1;
        else if (proto_str == "igmp") target_proto = 2;
        else if (proto_str == "tcp") target_proto = 6;
        else if (proto_str == "udp") target_proto = 17;
        else target_proto = std::stoi(proto_str);
    }
    
    switch (ip_proto_opt.op) {
        case Operator::EQUAL:
            return packet.ip_proto == target_proto;
        case Operator::NOT_EQUAL:
            return packet.ip_proto != target_proto;
        case Operator::GREATER_THAN:
            return packet.ip_proto > target_proto;
        case Operator::LESS_THAN:
            return packet.ip_proto < target_proto;
        case Operator::GREATER_EQUAL:
            return packet.ip_proto >= target_proto;
        case Operator::LESS_EQUAL:
            return packet.ip_proto <= target_proto;
        case Operator::RANGE_INCLUSIVE:
        case Operator::RANGE_EXCLUSIVE:
            // TODO: Implement range checking when max_value is available
            return true;
    }
    
    return false;
}

bool headerDetection(const Rule &rule, PacketInfo &packet, const NetworkConfig &conf) {
    // 1. Check service configuration
    if (!isServiceEnabled(rule, conf)) {
        return false;
    }

    // 2. Check protocol
    if (!rule.protocol) return false;
    
    if (*rule.protocol == "ip") {
        // IP rules: check ip_proto if specified
        if (!checkIPProtocol(rule, packet)) {
            return false;
        }
    } else {
        // Protocol-specific rules: exact match required
        if (*rule.protocol != packet.protocol) {
            return false;
        }
    }

    // 3. Check addresses and direction
    if (!checkAddressMatch(rule, packet, conf)) {
        return false;
    }

    // 4. Check ports (skip for IP rules)
    if (*rule.protocol != "ip") {
        if (!checkPortMatch(rule, packet)) {
            return false;
        }
    }

    return true;
}

bool headerDetection(PacketInfo &packet, std::map<std::string, std::vector<Rule>> &rules, const NetworkConfig &conf) {
    // Check IP rules first (covers all protocols)
    if(rules.find("ip") != rules.end()) {
        for (const auto &ip_rule : rules["ip"]) {
            if (headerDetection(ip_rule, packet, conf)) {
                return true;
            }
        }
    }

    // Check protocol-specific rules
    if (rules.find(packet.protocol) != rules.end()) {
        for (const auto &protocol_rule : rules[packet.protocol]) {
            if (headerDetection(protocol_rule, packet, conf)) {
                return true;
            }
        }
    }

    return false;
}

#endif