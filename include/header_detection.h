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
#include <optional>

// 🌐 แทนค่า $HOME_NET หรือ $EXTERNAL_NET
std::string resolveVariable(const std::string& var, const NetworkConfig& conf) {
    if (var == "$HOME_NET" && conf.HOME_NET) return *conf.HOME_NET;
    if (var == "$EXTERNAL_NET" && conf.EXTERNAL_NET) return *conf.EXTERNAL_NET;
    return var;
}

// ✅ ตรวจว่า IP ตรงกับ HOME_NET หรือไม่
bool isHomeNet(const std::string& ip, const NetworkConfig& conf) {
    return ip == *conf.HOME_NET;
}

// ✅ ตรวจว่า IP เป็น External หรือไม่
bool isExternalNet(const std::string& ip, const NetworkConfig& conf) {
    return ip != *conf.HOME_NET;
}

// ✅ ตรวจ IP field
bool matchIP(const std::string& rule_ip, const std::string& packet_ip, const NetworkConfig& conf) {
    if (rule_ip == "any") return true;
    if (rule_ip == "HOME_NET") return isHomeNet(packet_ip, conf);
    if (rule_ip == "EXTERNAL_NET") return isExternalNet(packet_ip, conf);
    return rule_ip == packet_ip;
}

// ✅ ตรวจ Port field
bool matchPort(const std::string& rule_port, uint16_t packet_port) {
    if (rule_port == "any") return true;
    return rule_port == std::to_string(packet_port);
}

// ✅ ตรวจว่าเปิด service ใน conf หรือไม่
bool isServiceEnabledForRule(const Rule& rule, const NetworkConfig& conf) {
    if (!rule.protocol) return false;
    std::string proto = *rule.protocol;

    if (proto == "http" || proto == "tcp") {
        if (conf.HTTP_SERVERS.value_or(false)) return true;
    }
    if (proto == "ftp") {
        if (conf.FTP_SERVERS.value_or(false)) return true;
    }
    if (proto == "smtp") {
        if (conf.SMTP_SERVERS.value_or(false)) return true;
    }
    if (proto == "sip" || proto == "udp") {
        if (conf.SIP_SERVERS.value_or(false)) return true;
    }
    if (proto == "telnet") {
        if (conf.TELNET_SERVERS.value_or(false)) return true;
    }
    return true;
}

// ✅ ตรวจทิศทางของ flow
bool checkDirection(const std::string& rule_dir, FlowDirection flow) {
    if (rule_dir == "->") return flow == FlowDirection::TO_SERVER;
    if (rule_dir == "<-") return flow == FlowDirection::TO_CLIENT;
    return true; // รองรับ <>, ไม่ระบุ
}

// ✅ ตรวจว่าที่อยู่ source/dest ตรงกับ rule หรือไม่
bool checkAddressMatch(const Rule &rule, PacketInfo &packet, const NetworkConfig &conf) {
    if (!rule.direction || !rule.src_addr || !rule.dst_addr) return false;

    std::string resolved_src = resolveVariable(*rule.src_addr, conf);
    std::string resolved_dst = resolveVariable(*rule.dst_addr, conf);

    if (*rule.direction == "->") {
        return matchIP(resolved_src, packet.src_addr, conf) &&
               matchIP(resolved_dst, packet.dst_addr, conf);
    } else if (*rule.direction == "<>") {
        return (matchIP(resolved_src, packet.src_addr, conf) && matchIP(resolved_dst, packet.dst_addr, conf)) ||
               (matchIP(resolved_dst, packet.src_addr, conf) && matchIP(resolved_src, packet.dst_addr, conf));
    }
    return false;
}

// ✅ ตรวจว่า port ตรงหรือไม่
bool checkPortMatch(const Rule &rule, PacketInfo &packet) {
    uint16_t sport = 0, dport = 0;

    if (packet.protocol == "tcp" && packet.tcp) {
        sport = static_cast<uint16_t>(std::stoi(packet.tcp->sport));
        dport = static_cast<uint16_t>(std::stoi(packet.tcp->dport));
    } else if (packet.protocol == "udp" && packet.udp) {
        sport = static_cast<uint16_t>(std::stoi(packet.udp->sport));
        dport = static_cast<uint16_t>(std::stoi(packet.udp->dport));
    } else {
        return true; // ICMP หรือ IP-only ไม่มี port
    }

    if (rule.src_port && !matchPort(*rule.src_port, sport)) return false;
    if (rule.dst_port && !matchPort(*rule.dst_port, dport)) return false;

    return true;
}

// ✅ ตรวจว่า ip_proto ตรงกับที่ระบุใน rule หรือไม่
bool checkIPProtocol(const Rule &rule, PacketInfo &packet) {
    if (!rule.option.nonpayload.ip_proto) return true;

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
        case Operator::EQUAL: return packet.ip_proto == target_proto;
        case Operator::NOT_EQUAL: return packet.ip_proto != target_proto;
        case Operator::GREATER_THAN: return packet.ip_proto > target_proto;
        case Operator::LESS_THAN: return packet.ip_proto < target_proto;
        case Operator::GREATER_EQUAL: return packet.ip_proto >= target_proto;
        case Operator::LESS_EQUAL: return packet.ip_proto <= target_proto;
        case Operator::RANGE_INCLUSIVE:
        case Operator::RANGE_EXCLUSIVE:
            return true;
    }
    return false;
}

// ✅ ฟังก์ชันหลัก ตรวจ rule เดี่ยวกับ packet เดี่ยว
bool headerDetection(const Rule &rule, PacketInfo &packet, const NetworkConfig &conf) {
    if (!rule.protocol) return false;

    if (!isServiceEnabledForRule(rule, conf)) return false;

    if (*rule.protocol != "ip" && *rule.protocol != packet.protocol) return false;

    if (*rule.protocol == "ip" && !checkIPProtocol(rule, packet)) return false;

    if (!checkAddressMatch(rule, packet, conf)) return false;

    if (!rule.direction || !packet.flow.direction.has_value()) return false;
    if (!checkDirection(*rule.direction, *packet.flow.direction)) return false;

    if (*rule.protocol != "ip" && !checkPortMatch(rule, packet)) return false;

    return true;
}

// ✅ ตรวจ packet กับ rule ทั้งหมดใน map ตาม protocol
bool headerDetection(PacketInfo &packet, std::map<std::string, std::vector<Rule>> &rules, const NetworkConfig &conf) {
    if (rules.find("ip") != rules.end()) {
        for (const auto &r : rules["ip"]) {
            if (headerDetection(r, packet, conf)) return true;
        }
    }
    if (rules.find(packet.protocol) != rules.end()) {
        for (const auto &r : rules[packet.protocol]) {
            if (headerDetection(r, packet, conf)) return true;
        }
    }
    return false;
}

#endif
