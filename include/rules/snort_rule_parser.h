#ifndef SNORT_RULE_PARSER_H
#define SNORT_RULE_PARSER_H

#include "snort_rule.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <unordered_map>

class SnortRuleParser {
private:
  // Helper functions for parsing
  static std::string trim(const std::string &str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
      return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
  }

  static std::string unescapeContent(const std::string &content) {
    std::string result = content;
    std::regex hex_pattern(R"(\|([0-9A-Fa-f]{2})\|)");
    std::smatch match;

    while (std::regex_search(result, match, hex_pattern)) {
      int hex_val = std::stoi(match[1].str(), nullptr, 16);
      char hex_char = static_cast<char>(hex_val);
      result = std::regex_replace(result, hex_pattern, std::string(1, hex_char),
                                  std::regex_constants::format_first_only);
    }

    // Handle other escape sequences
    size_t pos = 0;
    while ((pos = result.find("\\\"", pos)) != std::string::npos) {
      result.replace(pos, 2, "\"");
      pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\\\\", pos)) != std::string::npos) {
      result.replace(pos, 2, "\\");
      pos += 1;
    }

    return result;
  }

  static ClassType parseClassType(const std::string &classtype_str) {
    static std::unordered_map<std::string, ClassType> classtype_map = {
        {"attempted-user", ClassType::ATTEMPTED_USER},
        {"unsuccessful-user", ClassType::UNSUCCESSFUL_USER},
        {"successful-user", ClassType::SUCCESSFUL_USER},
        {"attempted-admin", ClassType::ATTEMPTED_ADMIN},
        {"successful-admin", ClassType::SUCCESSFUL_ADMIN},
        {"shellcode-detect", ClassType::SHELLCODE_DETECT},
        {"trojan-activity", ClassType::TROJAN_ACTIVITY},
        {"web-application-attack", ClassType::WEB_APPLICATION_ATTACK},
        {"inappropriate-content", ClassType::INAPPROPRIATE_CONTENT},
        {"policy-violation", ClassType::POLICY_VIOLATION},
        {"malware-cnc", ClassType::MALWARE_CNC},
        {"client-side-exploit", ClassType::CLIENT_SIDE_EXPLOIT},
        {"bad-unknown", ClassType::BAD_UNKNOWN},
        {"attempted-recon", ClassType::ATTEMPTED_RECON},
        {"successful-recon-limited", ClassType::SUCCESSFUL_RECON_LIMITED},
        {"successful-recon-largescale", ClassType::SUCCESSFUL_RECON_LARGESCALE},
        {"attempted-dos", ClassType::ATTEMPTED_DOS},
        {"successful-dos", ClassType::SUCCESSFUL_DOS},
        {"denial-of-service", ClassType::DENIAL_OF_SERVICE},
        {"rpc-portmap-decode", ClassType::RPC_PORTMAP_DECODE},
        {"suspicious-filename-detect", ClassType::SUSPICIOUS_FILENAME_DETECT},
        {"suspicious-login", ClassType::SUSPICIOUS_LOGIN},
        {"system-call-detect", ClassType::SYSTEM_CALL_DETECT},
        {"unusual-client-port-connection",
         ClassType::UNUSUAL_CLIENT_PORT_CONNECTION},
        {"non-standard-protocol", ClassType::NON_STANDARD_PROTOCOL},
        {"web-application-activity", ClassType::WEB_APPLICATION_ACTIVITY},
        {"misc-attack", ClassType::MISC_ATTACK},
        {"default-login-attempt", ClassType::DEFAULT_LOGIN_ATTEMPT},
        {"not-suspicious", ClassType::NOT_SUSPICIOUS},
        {"unknown", ClassType::UNKNOWN},
        {"string-detect", ClassType::STRING_DETECT},
        {"network-scan", ClassType::NETWORK_SCAN},
        {"protocol-command-decode", ClassType::PROTOCOL_COMMAND_DECODE},
        {"misc-activity", ClassType::MISC_ACTIVITY},
        {"icmp-event", ClassType::ICMP_EVENT},
        {"tcp-connection", ClassType::TCP_CONNECTION}};

    auto it = classtype_map.find(classtype_str);
    return (it != classtype_map.end()) ? it->second : ClassType::UNKNOWN;
  }

  static Operator parseOperator(const std::string &op_str) {
    if (op_str == ">")
      return Operator::GREATER_THAN;
    if (op_str == "<")
      return Operator::LESS_THAN;
    if (op_str == "!")
      return Operator::NOT_EQUAL;
    if (op_str == ">=")
      return Operator::GREATER_EQUAL;
    if (op_str == "<=")
      return Operator::LESS_EQUAL;
    if (op_str == "<>")
      return Operator::RANGE_EXCLUSIVE;
    return Operator::EQUAL;
  }

  static ByteTestOperator parseByteTestOperator(const std::string &op_str) {
    if (op_str == "<")
      return ByteTestOperator::LESS_THAN;
    if (op_str == ">")
      return ByteTestOperator::GREATER_THAN;
    if (op_str == "<=")
      return ByteTestOperator::LESS_EQUAL;
    if (op_str == ">=")
      return ByteTestOperator::GREATER_EQUAL;
    if (op_str == "=")
      return ByteTestOperator::EQUAL;
    if (op_str == "&")
      return ByteTestOperator::BITWISE_AND;
    if (op_str == "^")
      return ByteTestOperator::BITWISE_XOR;
    return ByteTestOperator::EQUAL;
  }

  static Buffer parseBuffer(const std::string &buffer_str) {
    static std::unordered_map<std::string, Buffer> buffer_map = {
        {"pkt_data", Buffer::PKT_DATA},
        {"raw_data", Buffer::RAW_DATA},
        {"base64_data", Buffer::BASE64_DATA},
        {"file_data", Buffer::FILE_DATA},
        {"http_client_body", Buffer::HTTP_CLIENT_BODY},
        {"http_raw_body", Buffer::HTTP_RAW_BODY},
        {"http_cookie", Buffer::HTTP_COOKIE},
        {"http_raw_cookie", Buffer::HTTP_RAW_COOKIE},
        {"http_header", Buffer::HTTP_HEADER},
        {"http_raw_header", Buffer::HTTP_RAW_HEADER},
        {"http_method", Buffer::HTTP_METHOD},
        {"http_uri", Buffer::HTTP_URI},
        {"http_raw_uri", Buffer::HTTP_RAW_URI},
        {"http_stat_code", Buffer::HTTP_STAT_CODE},
        {"http_stat_msg", Buffer::HTTP_STAT_MSG},
        {"http_true_ip", Buffer::HTTP_TRUE_IP},
        {"dce_iface", Buffer::DCE_IFACE},
        {"dce_opnum", Buffer::DCE_OPNUM},
        {"dce_stub_data", Buffer::DCE_STUB_DATA},
        {"ssl_state", Buffer::SSL_STATE},
        {"ssl_version", Buffer::SSL_VERSION},
        {"sip_header", Buffer::SIP_HEADER},
        {"sip_body", Buffer::SIP_BODY}};

    auto it = buffer_map.find(buffer_str);
    return (it != buffer_map.end()) ? it->second : Buffer::NONE;
  }

  static Endianness parseEndianness(const std::string &endian_str) {
    if (endian_str == "big")
      return Endianness::BIG;
    if (endian_str == "little")
      return Endianness::LITTLE;
    return Endianness::BIG; // default
  }

  static Width parseWidth(const std::string &width_str) {
    if (width_str == "8")
      return Width::BITS_8;
    if (width_str == "16")
      return Width::BITS_16;
    if (width_str == "32")
      return Width::BITS_32;
    return Width::BITS_8; // default
  }

public:
  static std::map<std::string, std::vector<Rule>>
  parseRulesFromFile(const std::string &filename) {
    std::map<std::string, std::vector<Rule>> rules_by_protocol;
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
      std::cerr << "Error: Cannot open file " << filename << std::endl;
      return rules_by_protocol;
    }

    std::string current_rule;
    while (std::getline(file, line)) {
      line = trim(line);

      // Skip comments and empty lines
      if (line.empty() || line[0] == '#')
        continue;

      // Handle multi-line rules
      current_rule += line;
      if (line.back() != '\\' && current_rule.find('(') != std::string::npos &&
          current_rule.find(')') != std::string::npos) {

        try {
          Rule rule = parseRule(current_rule);

          // Group by protocol
          std::string protocol = rule.protocol.value_or("unknown");
          rules_by_protocol[protocol].push_back(rule);
        } catch (const std::exception &e) {
          std::cerr << "Warning: Failed to parse rule: " << current_rule
                    << std::endl;
          std::cerr << "Error: " << e.what() << std::endl;
        }
        current_rule.clear();
      } else if (line.back() == '\\') {
        current_rule.pop_back(); // Remove backslash
        current_rule += " ";     // Add space
      }
    }

    file.close();
    return rules_by_protocol;
  }
  static Rule parseRule(const std::string &rule_text) {
    Rule rule;

    // Enhanced regex to handle various rule formats
    // Pattern 1: Full format: action protocol src_addr src_port direction
    // dst_addr dst_port
    std::regex header_regex1(
        R"(^(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+(->|<>|<-)\s+([^\s]+)\s+([^\s]+)\s*\(\s*(.*?)\s*\)$)");
    // Pattern 2: Simplified format: action protocol ( options )
    std::regex header_regex2(R"(^(\w+)\s+(\w+)\s*\(\s*(.*?)\s*\)$)");
    // Pattern 3: Mixed format: action protocol some_params ( options )
    std::regex header_regex3(R"(^(\w+)\s+(\w+)\s+([^(]+?)\s*\(\s*(.*?)\s*\)$)");

    std::smatch header_match;

    if (std::regex_match(rule_text, header_match, header_regex1)) {
      // Full format
      rule.action = header_match[1].str();
      rule.protocol = header_match[2].str();
      rule.src_addr = header_match[3].str();
      rule.src_port = header_match[4].str();
      rule.direction = header_match[5].str();
      rule.dst_addr = header_match[6].str();
      rule.dst_port = header_match[7].str();

      std::string options_text = header_match[8].str();
      parseOptions(options_text, rule.option);
    } else if (std::regex_match(rule_text, header_match, header_regex2)) {
      // Simplified format (like alert http ( ... ))
      rule.action = header_match[1].str();
      rule.protocol = header_match[2].str();
      // Set defaults for missing fields
      rule.src_addr = "any";
      rule.src_port = "any";
      rule.direction = "->";
      rule.dst_addr = "any";
      rule.dst_port = "any";

      std::string options_text = header_match[3].str();
      parseOptions(options_text, rule.option);
    } else if (std::regex_match(rule_text, header_match, header_regex3)) {
      // Mixed format - try to parse network parameters from middle part
      rule.action = header_match[1].str();
      rule.protocol = header_match[2].str();

      std::string middle_part = trim(header_match[3].str());
      parseNetworkParameters(middle_part, rule);

      std::string options_text = header_match[4].str();
      parseOptions(options_text, rule.option);
    } else {
      throw std::runtime_error("Invalid rule format: " +
                               rule_text.substr(0, 100));
    }

    return rule;
  }

private:
  // Track current buffer for sticky keywords
  static Buffer current_buffer;

  // Helper function to parse network parameters from middle part of rule
  static void parseNetworkParameters(const std::string &params, Rule &rule) {
    // Default values
    rule.src_addr = "any";
    rule.src_port = "any";
    rule.direction = "->";
    rule.dst_addr = "any";
    rule.dst_port = "any";

    // Try to extract network parameters if present
    std::vector<std::string> parts;
    std::stringstream ss(params);
    std::string part;

    while (ss >> part) {
      parts.push_back(part);
    }

    // If we have 5 parts, it's: src_addr src_port direction dst_addr dst_port
    if (parts.size() == 5) {
      rule.src_addr = parts[0];
      rule.src_port = parts[1];
      rule.direction = parts[2];
      rule.dst_addr = parts[3];
      rule.dst_port = parts[4];
    }
    // If we have 3 parts, might be: direction dst_addr dst_port
    else if (parts.size() == 3 &&
             (parts[0] == "->" || parts[0] == "<>" || parts[0] == "<-")) {
      rule.direction = parts[0];
      rule.dst_addr = parts[1];
      rule.dst_port = parts[2];
    }
  }

  static void parseOptions(const std::string &options_text,
                           RuleOption &rule_option) {
    // Reset current buffer
    current_buffer = Buffer::NONE;

    // Split options by semicolon, but handle quoted strings properly
    std::vector<std::string> options;
    std::string current_option;
    bool in_quotes = false;
    bool escaped = false;

    for (size_t i = 0; i < options_text.length(); i++) {
      char c = options_text[i];

      if (escaped) {
        current_option += c;
        escaped = false;
        continue;
      }

      if (c == '\\') {
        escaped = true;
        current_option += c;
        continue;
      }

      if (c == '"') {
        in_quotes = !in_quotes;
        current_option += c;
        continue;
      }

      if (c == ';' && !in_quotes) {
        if (!current_option.empty()) {
          options.push_back(trim(current_option));
          current_option.clear();
        }
      } else {
        current_option += c;
      }
    }

    if (!current_option.empty()) {
      options.push_back(trim(current_option));
    }

    // Parse individual options
    for (const auto &option : options) {
      parseIndividualOption(option, rule_option);
    }
  }

  static void parseIndividualOption(const std::string &option,
                                    RuleOption &rule_option) {
    // Handle complex options with multiple comma-separated values and spaces
    std::regex option_regex(R"(^([^:]+?)(?::(.*))?$)");
    std::smatch option_match;

    if (!std::regex_match(option, option_match, option_regex)) {
      return; // Skip invalid options
    }

    std::string option_name = trim(option_match[1].str());
    std::string option_value =
        option_match.size() > 2 ? trim(option_match[2].str()) : "";

    // Handle special cases for option names with spaces
    if (option_name.find("http_header") == 0) {
      current_buffer = Buffer::HTTP_HEADER;
      return; // Skip field specification
    }

    // Parse based on option name
    if (option_name == "msg") {
      // Remove quotes from value if present
      if (option_value.length() >= 2 && option_value[0] == '"' &&
          option_value.back() == '"') {
        option_value = option_value.substr(1, option_value.length() - 2);
      }
      rule_option.general.msg = option_value;
    } else if (option_name == "gid") {
      if (!option_value.empty()) {
        rule_option.general.gid =
            static_cast<uint16_t>(std::stoi(option_value));
      }
    } else if (option_name == "sid") {
      if (!option_value.empty()) {
        rule_option.general.sid =
            static_cast<uint16_t>(std::stoi(option_value));
      }
    } else if (option_name == "classtype") {
      rule_option.general.classtype = parseClassType(option_value);
    } else if (option_name == "service") {
      // Parse service list
      std::vector<std::string> services;
      std::stringstream ss(option_value);
      std::string service;
      while (std::getline(ss, service, ',')) {
        services.push_back(trim(service));
      }
      rule_option.general.service = services;
    } else if (option_name == "rev") {
      // Skip rev option - just for versioning
    } else if (option_name == "metadata") {
      // Skip metadata option - just for rule management
    } else if (option_name == "reference") {
      // Skip reference option - just for documentation
    }
    // Parse buffer modifiers (sticky keywords) with potential arguments
    else if (option_name == "http_uri") {
      current_buffer = Buffer::HTTP_URI;
    } else if (option_name == "http_raw_uri") {
      current_buffer = Buffer::HTTP_RAW_URI;
    } else if (option_name == "http_cookie") {
      current_buffer = Buffer::HTTP_COOKIE;
    } else if (option_name == "http_raw_cookie") {
      current_buffer = Buffer::HTTP_RAW_COOKIE;
    } else if (option_name == "http_client_body") {
      current_buffer = Buffer::HTTP_CLIENT_BODY;
    } else if (option_name == "http_raw_body") {
      current_buffer = Buffer::HTTP_RAW_BODY;
    } else if (option_name == "http_method") {
      current_buffer = Buffer::HTTP_METHOD;
    } else if (option_name == "http_stat_code") {
      current_buffer = Buffer::HTTP_STAT_CODE;
    } else if (option_name == "http_stat_msg") {
      current_buffer = Buffer::HTTP_STAT_MSG;
    } else if (option_name == "http_true_ip") {
      current_buffer = Buffer::HTTP_TRUE_IP;
    } else if (option_name == "http_raw_header") {
      current_buffer = Buffer::HTTP_RAW_HEADER;
    } else if (option_name == "file_data") {
      current_buffer = Buffer::FILE_DATA;
    } else if (option_name == "pkt_data") {
      current_buffer = Buffer::PKT_DATA;
    } else if (option_name == "raw_data") {
      current_buffer = Buffer::RAW_DATA;
    } else if (option_name == "base64_data") {
      current_buffer = Buffer::BASE64_DATA;
    } else if (option_name == "dce_iface") {
      current_buffer = Buffer::DCE_IFACE;
    } else if (option_name == "dce_opnum") {
      current_buffer = Buffer::DCE_OPNUM;
    } else if (option_name == "dce_stub_data") {
      current_buffer = Buffer::DCE_STUB_DATA;
    } else if (option_name == "sip_header") {
      current_buffer = Buffer::SIP_HEADER;
    } else if (option_name == "sip_body") {
      current_buffer = Buffer::SIP_BODY;
    }

    // Parse content options with modifiers
    else if (option_name == "content") {
      parseContentWithModifiers(option_value, rule_option.payload);
    }
    // Parse content modifiers that appear as separate options
    else if (option_name == "depth" && !rule_option.payload.content.empty()) {
      if (!option_value.empty()) {
        rule_option.payload.content.back().depth = std::stoi(option_value);
      }
    } else if (option_name == "offset" &&
               !rule_option.payload.content.empty()) {
      if (!option_value.empty()) {
        rule_option.payload.content.back().offset = std::stoi(option_value);
      }
    } else if (option_name == "distance" &&
               !rule_option.payload.content.empty()) {
      if (!option_value.empty()) {
        rule_option.payload.content.back().distance = std::stoi(option_value);
      }
    } else if (option_name == "within" &&
               !rule_option.payload.content.empty()) {
      if (!option_value.empty()) {
        rule_option.payload.content.back().within = std::stoi(option_value);
      }
    } else if (option_name == "nocase" &&
               !rule_option.payload.content.empty()) {
      rule_option.payload.content.back().nocase = true;
    } else if (option_name == "fast_pattern") {
      if (!rule_option.payload.content.empty()) {
        if (option_value.empty()) {
          rule_option.payload.content.back().fast_pattern = true;
        } else if (option_value == "only") {
          rule_option.payload.content.back().fast_pattern_only = true;
        } else {
          // Parse fast_pattern:offset,length
          std::regex fp_regex(R"(^(\d+),(\d+)$)");
          std::smatch fp_match;
          if (std::regex_match(option_value, fp_match, fp_regex)) {
            rule_option.payload.content.back().fast_pattern = true;
            rule_option.payload.content.back().fast_pattern_offset =
                std::stoi(fp_match[1].str());
            rule_option.payload.content.back().fast_pattern_length =
                std::stoi(fp_match[2].str());
          }
        }
      }
    } else if (option_name == "fast_pattern_only" &&
               !rule_option.payload.content.empty()) {
      rule_option.payload.content.back().fast_pattern_only = true;
    }
    // Parse other payload options
    else if (option_name == "pcre") {
      parsePCREOption(option_value, rule_option.payload);
    } else if (option_name == "dsize") {
      parseDsizeOption(option_value, rule_option.payload);
    } else if (option_name == "isdataat") {
      parseIsDataAtOption(option_value, rule_option.payload);
    } else if (option_name == "bufferlen") {
      parseBufferLenOption(option_value, rule_option.payload);
    } else if (option_name == "byte_extract") {
      parseByteExtractOption(option_value, rule_option.payload);
    } else if (option_name == "byte_test") {
      parseByteTestOption(option_value, rule_option.payload);
    } else if (option_name == "byte_jump") {
      parseByteJumpOption(option_value, rule_option.payload);
    } else if (option_name == "base64_decode") {
      parseBase64DecodeOption(option_value, rule_option.payload);
    } else if (option_name == "ber_data") {
      // Parse BER data option
      if (!option_value.empty()) {
        BerData ber_data;
        ber_data.type = static_cast<uint8_t>(
            std::stoi(option_value, nullptr, 0)); // Support hex
        if (!rule_option.payload.ber_data_list) {
          rule_option.payload.ber_data_list = std::vector<BerData>();
        }
        rule_option.payload.ber_data_list->push_back(ber_data);
      }
    } else if (option_name == "ber_skip") {
      // Parse BER skip option
      if (!option_value.empty()) {
        BerSkip ber_skip;

        // Parse format: ber_skip:0x01,optional
        std::vector<std::string> parts;
        std::stringstream ss(option_value);
        std::string part;
        while (std::getline(ss, part, ',')) {
          parts.push_back(trim(part));
        }

        if (!parts.empty()) {
          ber_skip.type = static_cast<uint8_t>(std::stoi(parts[0], nullptr, 0));
          for (size_t i = 1; i < parts.size(); i++) {
            if (parts[i] == "optional") {
              ber_skip.optional = true;
            }
          }
        }

        if (!rule_option.payload.ber_skip_list) {
          rule_option.payload.ber_skip_list = std::vector<BerSkip>();
        }
        rule_option.payload.ber_skip_list->push_back(ber_skip);
      }
    } else if (option_name == "ssl_state") {
      parseSSLStateOption(option_value, rule_option.payload);
    } else if (option_name == "ssl_version") {
      parseSSLVersionOption(option_value, rule_option.payload);
    }
    // Parse flow options
    else if (option_name == "flow") {
      parseFlowOption(option_value, rule_option.nonpayload);
    } else if (option_name == "flowbits") {
      parseFlowBitsOption(option_value, rule_option.nonpayload);
    }
    // Parse TCP flags
    else if (option_name == "flags") {
      parseFlagsOption(option_value, rule_option.nonpayload);
    }
    // Parse TTL
    else if (option_name == "ttl") {
      parseTTLOption(option_value, rule_option.nonpayload);
    }
    // Parse ID
    else if (option_name == "id") {
      parseIDOption(option_value, rule_option.nonpayload);
    }
    // Parse fragbits
    else if (option_name == "fragbits") {
      parseFragbitsOption(option_value, rule_option.nonpayload);
    }
    // Parse ip_proto
    else if (option_name == "ip_proto") {
      parseIPProtoOption(option_value, rule_option.nonpayload);
    }
    // Parse ICMP options
    else if (option_name == "itype") {
      parseITypeOption(option_value, rule_option.nonpayload);
    } else if (option_name == "icode") {
      parseICodeOption(option_value, rule_option.nonpayload);
    } else if (option_name == "icmp_id") {
      parseICMP_IDOption(option_value, rule_option.nonpayload);
    } else if (option_name == "icmp_seq") {
      parseICMP_SEQOption(option_value, rule_option.nonpayload);
    }
    // Parse sequence numbers
    else if (option_name == "seq") {
      parseSEQOption(option_value, rule_option.nonpayload);
    } else if (option_name == "ack") {
      parseACKOption(option_value, rule_option.nonpayload);
    }
    // Skip unknown options
    else {
      // Uncomment for debugging: std::cout << "Skipping unknown option: " <<
      // option_name << std::endl;
    }
  }

  static void parseContentWithModifiers(const std::string &value,
                                        PayloadOption &payload) {
    Content content;

    // Split by comma to separate content value from modifiers
    std::vector<std::string> parts;
    std::string current_part;
    bool in_quotes = false;
    bool escaped = false;

    for (size_t i = 0; i < value.length(); i++) {
      char c = value[i];

      if (escaped) {
        current_part += c;
        escaped = false;
        continue;
      }

      if (c == '\\') {
        escaped = true;
        current_part += c;
        continue;
      }

      if (c == '"') {
        in_quotes = !in_quotes;
        current_part += c;
        continue;
      }

      if (c == ',' && !in_quotes) {
        if (!current_part.empty()) {
          parts.push_back(trim(current_part));
          current_part.clear();
        }
      } else {
        current_part += c;
      }
    }

    if (!current_part.empty()) {
      parts.push_back(trim(current_part));
    }

    if (parts.empty())
      return;

    // First part is the content value
    std::string content_str = parts[0];

    // Check for negation in content
    if (!content_str.empty() && content_str[0] == '!') {
      content.negate = true;
      content_str = content_str.substr(1);
    }

    // Remove quotes
    if (content_str.length() >= 2 && content_str[0] == '"' &&
        content_str.back() == '"') {
      content_str = content_str.substr(1, content_str.length() - 2);
    }

    content.content = unescapeContent(content_str);
    content.buffer = current_buffer; // Apply current buffer

    // Parse modifiers
    for (size_t i = 1; i < parts.size(); i++) {
      std::string modifier = trim(parts[i]);

      if (modifier == "fast_pattern") {
        content.fast_pattern = true;
      } else if (modifier == "fast_pattern_only") {
        content.fast_pattern_only = true;
      } else if (modifier == "nocase") {
        content.nocase = true;
      } else if (modifier.find("depth") == 0) {
        // Parse depth value: depth 10
        std::regex depth_regex(R"(^depth\s+(\d+)$)");
        std::smatch depth_match;
        if (std::regex_match(modifier, depth_match, depth_regex)) {
          content.depth = std::stoi(depth_match[1].str());
        }
      } else if (modifier.find("offset") == 0) {
        // Parse offset value: offset 5
        std::regex offset_regex(R"(^offset\s+([-\d]+)$)");
        std::smatch offset_match;
        if (std::regex_match(modifier, offset_match, offset_regex)) {
          content.offset = std::stoi(offset_match[1].str());
        }
      } else if (modifier.find("distance") == 0) {
        // Parse distance value: distance 0
        std::regex distance_regex(R"(^distance\s+([-\d]+)$)");
        std::smatch distance_match;
        if (std::regex_match(modifier, distance_match, distance_regex)) {
          content.distance = std::stoi(distance_match[1].str());
        }
      } else if (modifier.find("within") == 0) {
        // Parse within value: within 100
        std::regex within_regex(R"(^within\s+(\d+)$)");
        std::smatch within_match;
        if (std::regex_match(modifier, within_match, within_regex)) {
          content.within = std::stoi(within_match[1].str());
        }
      } else if (modifier == "big" || modifier == "endian big") {
        content.endian = Endianness::BIG;
      } else if (modifier == "little" || modifier == "endian little") {
        content.endian = Endianness::LITTLE;
      } else if (modifier.find("width") == 0) {
        // Parse width value: width 8/16/32
        std::regex width_regex(R"(^width\s+(\d+)$)");
        std::smatch width_match;
        if (std::regex_match(modifier, width_match, width_regex)) {
          content.width = parseWidth(width_match[1].str());
        }
      }
    }

    payload.content.push_back(content);
  }

  static void parseContentOption(const std::string &value,
                                 PayloadOption &payload) {
    Content content;

    // Check for negation
    std::string content_str = value;
    if (!content_str.empty() && content_str[0] == '!') {
      content.negate = true;
      content_str = content_str.substr(1);
    }

    // Remove quotes
    if (content_str.length() >= 2 && content_str[0] == '"' &&
        content_str.back() == '"') {
      content_str = content_str.substr(1, content_str.length() - 2);
    }

    content.content = unescapeContent(content_str);
    content.buffer = current_buffer; // Apply current buffer

    payload.content.push_back(content);
  }

  static void parsePCREOption(const std::string &value,
                              PayloadOption &payload) {
    PCRE pcre;

    // Check for negation
    std::string pcre_str = value;
    if (!pcre_str.empty() && pcre_str[0] == '!') {
      pcre.negate = true;
      pcre_str = pcre_str.substr(1);
    }

    // Parse PCRE pattern and flags
    std::regex pcre_regex(R"(^/(.+?)/([imsxAEGOR]*)$)");
    std::smatch pcre_match;

    if (std::regex_match(pcre_str, pcre_match, pcre_regex)) {
      pcre.pattern = pcre_match[1].str();
      std::string flags = pcre_match[2].str();

      pcre.i = flags.find('i') != std::string::npos;
      pcre.s = flags.find('s') != std::string::npos;
      pcre.m = flags.find('m') != std::string::npos;
      pcre.x = flags.find('x') != std::string::npos;
      pcre.A = flags.find('A') != std::string::npos;
      pcre.E = flags.find('E') != std::string::npos;
      pcre.G = flags.find('G') != std::string::npos;
      pcre.O = flags.find('O') != std::string::npos;
      pcre.R = flags.find('R') != std::string::npos;
    } else {
      pcre.pattern = pcre_str;
    }

    if (!payload.pcre) {
      payload.pcre = std::vector<PCRE>();
    }
    payload.pcre->push_back(pcre);
  }

  static void parseDsizeOption(const std::string &value,
                               PayloadOption &payload) {
    Dsize dsize;

    // Parse range format: dsize:10<>20 or dsize:>100 etc.
    std::regex range_regex(R"(^(\d+)<>(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      dsize.op = Operator::RANGE_EXCLUSIVE;
      dsize.min_value = static_cast<uint16_t>(std::stoi(match[1].str()));
      dsize.max_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      dsize.op = parseOperator(match[1].str());
      dsize.min_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    }

    payload.dsize = dsize;
  }

  static void parseIsDataAtOption(const std::string &value,
                                  PayloadOption &payload) {
    IsDataAt isdataat;

    // Parse format: isdataat:!10,relative or isdataat:20
    std::regex isdataat_regex(R"(^(!?)(\d+)(?:,(.*))?$)");
    std::smatch match;

    if (std::regex_match(value, match, isdataat_regex)) {
      isdataat.negate = !match[1].str().empty();
      isdataat.location = std::stoi(match[2].str());

      if (match.size() > 3 && !match[3].str().empty()) {
        std::string modifiers = match[3].str();
        if (modifiers.find("relative") != std::string::npos) {
          isdataat.relative = true;
        }
      }
    }

    if (!payload.isdataat) {
      payload.isdataat = std::vector<IsDataAt>();
    }
    payload.isdataat->push_back(isdataat);
  }

  static void parseBufferLenOption(const std::string &value,
                                   PayloadOption &payload) {
    BufferLen bufferlen;

    // Parse format similar to dsize
    std::regex range_regex(R"(^(\d+)<>(\d+)(?:,(.*))?$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)(?:,(.*))?$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      bufferlen.op = Operator::RANGE_EXCLUSIVE;
      bufferlen.min_value = std::stoi(match[1].str());
      bufferlen.max_value = std::stoi(match[2].str());

      if (match.size() > 3 && !match[3].str().empty()) {
        std::string modifiers = match[3].str();
        if (modifiers.find("relative") != std::string::npos) {
          bufferlen.relative = true;
        }
      }
    } else if (std::regex_match(value, match, operator_regex)) {
      bufferlen.op = parseOperator(match[1].str());
      bufferlen.min_value = std::stoi(match[2].str());

      if (match.size() > 3 && !match[3].str().empty()) {
        std::string modifiers = match[3].str();
        if (modifiers.find("relative") != std::string::npos) {
          bufferlen.relative = true;
        }
      }
    }

    if (!payload.bufferlen) {
      payload.bufferlen = std::vector<BufferLen>();
    }
    payload.bufferlen->push_back(bufferlen);
  }

  static void parseByteExtractOption(const std::string &value,
                                     PayloadOption &payload) {
    ByteExtract byte_extract;

    // Parse format: byte_extract:4,0,test_var,relative,big
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;

    while (std::getline(ss, part, ',')) {
      parts.push_back(trim(part));
    }

    if (parts.size() >= 3) {
      byte_extract.count = static_cast<uint8_t>(std::stoi(parts[0]));
      byte_extract.offset = std::stoi(parts[1]);
      byte_extract.variable_name = parts[2];

      // Parse modifiers
      for (size_t i = 3; i < parts.size(); i++) {
        std::string modifier = trim(parts[i]);
        if (modifier == "relative") {
          byte_extract.relative = true;
        } else if (modifier == "big") {
          byte_extract.endian = Endianness::BIG;
        } else if (modifier == "little") {
          byte_extract.endian = Endianness::LITTLE;
        } else if (modifier == "string") {
          byte_extract.string_format = true;
        } else if (modifier == "dce") {
          byte_extract.dce = true;
        } else if (modifier.find("multiplier") == 0) {
          // Parse multiplier value: multiplier 2
          std::regex mult_regex(R"(^multiplier\s+(\d+)$)");
          std::smatch mult_match;
          if (std::regex_match(modifier, mult_match, mult_regex)) {
            byte_extract.multiplier =
                static_cast<uint16_t>(std::stoi(mult_match[1].str()));
          }
        } else if (modifier.find("align") == 0) {
          // Parse align value: align 4
          std::regex align_regex(R"(^align\s+(\d+)$)");
          std::smatch align_match;
          if (std::regex_match(modifier, align_match, align_regex)) {
            byte_extract.align =
                static_cast<uint8_t>(std::stoi(align_match[1].str()));
          }
        } else if (modifier.find("base") == 0) {
          // Parse base value: base dec/hex/oct
          std::regex base_regex(R"(^base\s+(\w+)$)");
          std::smatch base_match;
          if (std::regex_match(modifier, base_match, base_regex)) {
            byte_extract.base = base_match[1].str();
          }
        } else if (modifier.find("bitmask") == 0) {
          // Parse bitmask value: bitmask 0xff
          std::regex bitmask_regex(R"(^bitmask\s+(0x[0-9a-fA-F]+|\d+)$)");
          std::smatch bitmask_match;
          if (std::regex_match(modifier, bitmask_match, bitmask_regex)) {
            std::string bitmask_str = bitmask_match[1].str();
            if (bitmask_str.find("0x") == 0) {
              byte_extract.bitmask = std::stoi(bitmask_str, nullptr, 16);
            } else {
              byte_extract.bitmask = std::stoi(bitmask_str);
            }
          }
        }
      }
    }

    if (!payload.byte_extracts) {
      payload.byte_extracts = std::vector<ByteExtract>();
    }
    payload.byte_extracts->push_back(byte_extract);
  }

  static void parseByteTestOption(const std::string &value,
                                  PayloadOption &payload) {
    ByteTest byte_test;

    // Parse format: byte_test:4,>,100,0,relative
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;

    while (std::getline(ss, part, ',')) {
      parts.push_back(trim(part));
    }

    if (parts.size() >= 4) {
      byte_test.count = static_cast<uint8_t>(std::stoi(parts[0]));
      byte_test.op = parseByteTestOperator(parts[1]);
      byte_test.compare_value = parts[2];
      byte_test.offset = parts[3];

      // Parse modifiers
      for (size_t i = 4; i < parts.size(); i++) {
        std::string modifier = trim(parts[i]);
        if (modifier == "relative") {
          byte_test.relative = true;
        } else if (modifier == "big") {
          byte_test.endian = Endianness::BIG;
        } else if (modifier == "little") {
          byte_test.endian = Endianness::LITTLE;
        } else if (modifier == "string") {
          byte_test.string_format = true;
        } else if (modifier == "dce") {
          byte_test.dce = true;
        } else if (modifier.find("base") == 0) {
          std::regex base_regex(R"(^base\s+(\w+)$)");
          std::smatch base_match;
          if (std::regex_match(modifier, base_match, base_regex)) {
            byte_test.base = base_match[1].str();
          }
        } else if (modifier.find("bitmask") == 0) {
          std::regex bitmask_regex(R"(^bitmask\s+(0x[0-9a-fA-F]+|\d+)$)");
          std::smatch bitmask_match;
          if (std::regex_match(modifier, bitmask_match, bitmask_regex)) {
            std::string bitmask_str = bitmask_match[1].str();
            if (bitmask_str.find("0x") == 0) {
              byte_test.bitmask = std::stoi(bitmask_str, nullptr, 16);
            } else {
              byte_test.bitmask = std::stoi(bitmask_str);
            }
          }
        }
      }
    }

    if (!payload.byte_tests) {
      payload.byte_tests = std::vector<ByteTest>();
    }
    payload.byte_tests->push_back(byte_test);
  }

  static void parseByteJumpOption(const std::string &value,
                                  PayloadOption &payload) {
    ByteJump byte_jump;

    // Parse format: byte_jump:4,0,relative,big
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;

    while (std::getline(ss, part, ',')) {
      parts.push_back(trim(part));
    }

    if (parts.size() >= 2) {
      byte_jump.count = static_cast<uint8_t>(std::stoi(parts[0]));
      byte_jump.offset = parts[1];

      // Parse modifiers
      for (size_t i = 2; i < parts.size(); i++) {
        std::string modifier = trim(parts[i]);
        if (modifier == "relative") {
          byte_jump.relative = true;
        } else if (modifier == "big") {
          byte_jump.endian = Endianness::BIG;
        } else if (modifier == "little") {
          byte_jump.endian = Endianness::LITTLE;
        } else if (modifier == "string") {
          byte_jump.string_format = true;
        } else if (modifier == "align") {
          byte_jump.align = true;
        } else if (modifier == "from_beginning") {
          byte_jump.from_beginning = true;
        } else if (modifier == "from_end") {
          byte_jump.from_end = true;
        } else if (modifier == "dce") {
          byte_jump.dce = true;
        } else if (modifier.find("multiplier") == 0) {
          std::regex mult_regex(R"(^multiplier\s+(\d+)$)");
          std::smatch mult_match;
          if (std::regex_match(modifier, mult_match, mult_regex)) {
            byte_jump.multiplier =
                static_cast<uint16_t>(std::stoi(mult_match[1].str()));
          }
        } else if (modifier.find("base") == 0) {
          std::regex base_regex(R"(^base\s+(\w+)$)");
          std::smatch base_match;
          if (std::regex_match(modifier, base_match, base_regex)) {
            byte_jump.base = base_match[1].str();
          }
        } else if (modifier.find("post_offset") == 0) {
          std::regex post_regex(R"(^post_offset\s+([-\d]+)$)");
          std::smatch post_match;
          if (std::regex_match(modifier, post_match, post_regex)) {
            byte_jump.post_offset = post_match[1].str();
          }
        } else if (modifier.find("bitmask") == 0) {
          std::regex bitmask_regex(R"(^bitmask\s+(0x[0-9a-fA-F]+|\d+)$)");
          std::smatch bitmask_match;
          if (std::regex_match(modifier, bitmask_match, bitmask_regex)) {
            std::string bitmask_str = bitmask_match[1].str();
            if (bitmask_str.find("0x") == 0) {
              byte_jump.bitmask = std::stoi(bitmask_str, nullptr, 16);
            } else {
              byte_jump.bitmask = std::stoi(bitmask_str);
            }
          }
        }
      }
    }

    if (!payload.byte_jumps) {
      payload.byte_jumps = std::vector<ByteJump>();
    }
    payload.byte_jumps->push_back(byte_jump);
  }

  static void parseBase64DecodeOption(const std::string &value,
                                      PayloadOption &payload) {
    Base64Decode base64_decode;

    if (!value.empty()) {
      // Parse format: base64_decode:bytes 100,offset 10,relative
      std::vector<std::string> parts;
      std::stringstream ss(value);
      std::string part;

      while (std::getline(ss, part, ',')) {
        part = trim(part);
        if (part.find("bytes") != std::string::npos) {
          std::regex bytes_regex(R"(^bytes\s+(\d+)$)");
          std::smatch bytes_match;
          if (std::regex_match(part, bytes_match, bytes_regex)) {
            base64_decode.bytes = std::stoi(bytes_match[1].str());
          }
        } else if (part.find("offset") != std::string::npos) {
          std::regex offset_regex(R"(^offset\s+(\d+)$)");
          std::smatch offset_match;
          if (std::regex_match(part, offset_match, offset_regex)) {
            base64_decode.offset = std::stoi(offset_match[1].str());
          }
        } else if (part == "relative") {
          base64_decode.relative = true;
        }
      }
    }

    payload.base64_decode = base64_decode;
  }

  static void parseSSLStateOption(const std::string &value,
                                  PayloadOption &payload) {
    SSLStateOption ssl_state;

    // Check for negation
    std::string state_str = value;
    if (!state_str.empty() && state_str[0] == '!') {
      ssl_state.negate = true;
      state_str = state_str.substr(1);
    }

    // Parse comma-separated states
    std::stringstream ss(state_str);
    std::string state;

    while (std::getline(ss, state, ',')) {
      state = trim(state);

      if (state == "client_hello")
        ssl_state.states.push_back(SSLState::CLIENT_HELLO);
      else if (state == "server_hello")
        ssl_state.states.push_back(SSLState::SERVER_HELLO);
      else if (state == "client_keyx")
        ssl_state.states.push_back(SSLState::CLIENT_KEYX);
      else if (state == "server_keyx")
        ssl_state.states.push_back(SSLState::SERVER_KEYX);
      else if (state == "unknown")
        ssl_state.states.push_back(SSLState::UNKNOWN);
    }

    payload.ssl_state = ssl_state;
  }

  static void parseSSLVersionOption(const std::string &value,
                                    PayloadOption &payload) {
    SSLVersionOption ssl_version;

    // Check for negation
    std::string version_str = value;
    if (!version_str.empty() && version_str[0] == '!') {
      ssl_version.negate = true;
      version_str = version_str.substr(1);
    }

    // Parse comma-separated versions
    std::stringstream ss(version_str);
    std::string version;

    while (std::getline(ss, version, ',')) {
      version = trim(version);

      if (version == "sslv2")
        ssl_version.versions.push_back(SSLVersion::SSLV2);
      else if (version == "sslv3")
        ssl_version.versions.push_back(SSLVersion::SSLV3);
      else if (version == "tls1.0")
        ssl_version.versions.push_back(SSLVersion::TLS1_0);
      else if (version == "tls1.1")
        ssl_version.versions.push_back(SSLVersion::TLS1_1);
      else if (version == "tls1.2")
        ssl_version.versions.push_back(SSLVersion::TLS1_2);
    }

    payload.ssl_version = ssl_version;
  }

  static void parseFlowOption(const std::string &value,
                              NonePayloadOption &nonpayload) {
    FlowOption flow;
    std::stringstream ss(value);
    std::string item;

    while (std::getline(ss, item, ',')) {
      item = trim(item);

      if (item == "established")
        flow.connection_state = FlowOption::ConnectionState::ESTABLISHED;
      else if (item == "not_established")
        flow.connection_state = FlowOption::ConnectionState::NOT_ESTABLISHED;
      else if (item == "stateless")
        flow.connection_state = FlowOption::ConnectionState::STATELESS;

      else if (item == "to_client")
        flow.direction = FlowOption::Direction::TO_CLIENT;
      else if (item == "to_server")
        flow.direction = FlowOption::Direction::TO_SERVER;
      else if (item == "from_client")
        flow.direction = FlowOption::Direction::FROM_CLIENT;
      else if (item == "from_server")
        flow.direction = FlowOption::Direction::FROM_SERVER;

      else if (item == "no_stream")
        flow.stream_mode = FlowOption::StreamMode::NO_STREAM;
      else if (item == "only_stream")
        flow.stream_mode = FlowOption::StreamMode::ONLY_STREAM;

      else if (item == "no_frag")
        flow.fragment_mode = FlowOption::FragmentMode::NO_FRAG;
      else if (item == "only_frag")
        flow.fragment_mode = FlowOption::FragmentMode::ONLY_FRAG;
    }

    nonpayload.flow = flow;
  }

  static void parseFlowBitsOption(const std::string &value,
                                  NonePayloadOption &nonpayload) {
    FlowBit flowbit;

    std::regex flowbit_regex(
        R"(^(set|unset|isset|isnotset|noalert)(?:,(.+))?$)");
    std::smatch flowbit_match;

    if (std::regex_match(value, flowbit_match, flowbit_regex)) {
      std::string op = flowbit_match[1].str();

      if (op == "set")
        flowbit.operation = FlowBit::Operation::SET;
      else if (op == "unset")
        flowbit.operation = FlowBit::Operation::UNSET;
      else if (op == "isset")
        flowbit.operation = FlowBit::Operation::ISSET;
      else if (op == "isnotset")
        flowbit.operation = FlowBit::Operation::ISNOTSET;
      else if (op == "noalert")
        flowbit.operation = FlowBit::Operation::NOALERT;

      if (flowbit_match.size() > 2 && !flowbit_match[2].str().empty()) {
        std::string flags = flowbit_match[2].str();

        // Parse flag names separated by & or |
        if (flags.find('&') != std::string::npos) {
          flowbit.logical_op = FlowBit::LogicalOperator::AND;
          std::stringstream ss(flags);
          std::string flag;
          while (std::getline(ss, flag, '&')) {
            flowbit.flag_names.push_back(trim(flag));
          }
        } else if (flags.find('|') != std::string::npos) {
          flowbit.logical_op = FlowBit::LogicalOperator::OR;
          std::stringstream ss(flags);
          std::string flag;
          while (std::getline(ss, flag, '|')) {
            flowbit.flag_names.push_back(trim(flag));
          }
        } else {
          flowbit.flag_names.push_back(flags);
        }
      }
    }

    if (!nonpayload.flowbits) {
      nonpayload.flowbits = std::vector<FlowBit>();
    }
    nonpayload.flowbits->push_back(flowbit);
  }

  static void parseFlagsOption(const std::string &value,
                               NonePayloadOption &nonpayload) {
    TCPFlags flags;

    // Parse modifier
    if (!value.empty()) {
      if (value[0] == '+') {
        flags.modifier = TCPFlags::Modifier::PLUS;
      } else if (value[0] == '*') {
        flags.modifier = TCPFlags::Modifier::ANY;
      } else if (value[0] == '!') {
        flags.modifier = TCPFlags::Modifier::NOT;
      } else {
        flags.modifier = TCPFlags::Modifier::EXACT;
      }
    }

    std::string flag_str = value;
    if (!flag_str.empty() &&
        (flag_str[0] == '+' || flag_str[0] == '*' || flag_str[0] == '!')) {
      flag_str = flag_str.substr(1);
    }

    // Parse individual flags
    for (char c : flag_str) {
      switch (c) {
      case 'F':
        flags.fin = true;
        break;
      case 'S':
        flags.syn = true;
        break;
      case 'R':
        flags.rst = true;
        break;
      case 'P':
        flags.psh = true;
        break;
      case 'A':
        flags.ack = true;
        break;
      case 'U':
        flags.urg = true;
        break;
      case 'E':
        flags.ece = true;
        break;
      case 'C':
        flags.cwr = true;
        break;
      }
    }

    nonpayload.flags = flags;
  }

  static void parseIPProtoOption(const std::string &value,
                                 NonePayloadOption &nonpayload) {
    IPProtoOption ip_proto;

    // Parse operator and protocol
    std::regex operator_regex(R"(^([<>=!]*)(.+)$)");
    std::smatch match;

    if (std::regex_match(value, match, operator_regex)) {
      ip_proto.op = parseOperator(match[1].str());
      std::string proto_str = match[2].str();

      // Check if it's a number or string
      if (std::all_of(proto_str.begin(), proto_str.end(), ::isdigit)) {
        ip_proto.protocol = static_cast<uint8_t>(std::stoi(proto_str));
      } else {
        ip_proto.protocol = proto_str;
      }
    }

    nonpayload.ip_proto = ip_proto;
  }

  static void parseTTLOption(const std::string &value,
                             NonePayloadOption &nonpayload) {
    TTL ttl;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      ttl.op = Operator::RANGE_INCLUSIVE;
      ttl.min_value = static_cast<uint8_t>(std::stoi(match[1].str()));
      ttl.max_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      ttl.op = parseOperator(match[1].str());
      ttl.min_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    }

    nonpayload.ttl = ttl;
  }

  static void parseIDOption(const std::string &value,
                            NonePayloadOption &nonpayload) {
    ID id;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      id.op = Operator::RANGE_INCLUSIVE;
      id.min_value = static_cast<uint16_t>(std::stoi(match[1].str()));
      id.max_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      id.op = parseOperator(match[1].str());
      id.min_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    }

    nonpayload.id = id;
  }

  static void parseFragbitsOption(const std::string &value,
                                  NonePayloadOption &nonpayload) {
    FragbitsOption fragbits;

    // Parse modifier
    if (!value.empty()) {
      if (value[0] == '+') {
        fragbits.modifier = FragbitsOption::Modifier::PLUS;
      } else if (value[0] == '*') {
        fragbits.modifier = FragbitsOption::Modifier::ANY;
      } else if (value[0] == '!') {
        fragbits.modifier = FragbitsOption::Modifier::NOT;
      } else {
        fragbits.modifier = FragbitsOption::Modifier::EXACT;
      }
    }

    std::string bits_str = value;
    if (!bits_str.empty() &&
        (bits_str[0] == '+' || bits_str[0] == '*' || bits_str[0] == '!')) {
      bits_str = bits_str.substr(1);
    }

    // Parse fragment bits
    for (char c : bits_str) {
      switch (c) {
      case 'M':
        fragbits.more_fragments = true;
        break;
      case 'D':
        fragbits.dont_fragment = true;
        break;
      case 'R':
        fragbits.reserved = true;
        break;
      }
    }

    nonpayload.fragbits = fragbits;
  }

  static void parseITypeOption(const std::string &value,
                               NonePayloadOption &nonpayload) {
    IType itype;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      itype.op = Operator::RANGE_INCLUSIVE;
      itype.min_value = static_cast<uint8_t>(std::stoi(match[1].str()));
      itype.max_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      itype.op = parseOperator(match[1].str());
      itype.min_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    }

    nonpayload.itype = itype;
  }

  static void parseICodeOption(const std::string &value,
                               NonePayloadOption &nonpayload) {
    ICode icode;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      icode.op = Operator::RANGE_INCLUSIVE;
      icode.min_value = static_cast<uint8_t>(std::stoi(match[1].str()));
      icode.max_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      icode.op = parseOperator(match[1].str());
      icode.min_value = static_cast<uint8_t>(std::stoi(match[2].str()));
    }

    nonpayload.icode = icode;
  }

  static void parseICMP_IDOption(const std::string &value,
                                 NonePayloadOption &nonpayload) {
    ICMP_ID icmp_id;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      icmp_id.op = Operator::RANGE_INCLUSIVE;
      icmp_id.min_value = static_cast<uint16_t>(std::stoi(match[1].str()));
      icmp_id.max_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      icmp_id.op = parseOperator(match[1].str());
      icmp_id.min_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    }

    nonpayload.icmp_id = icmp_id;
  }

  static void parseICMP_SEQOption(const std::string &value,
                                  NonePayloadOption &nonpayload) {
    ICMP_SEQ icmp_seq;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      icmp_seq.op = Operator::RANGE_INCLUSIVE;
      icmp_seq.min_value = static_cast<uint16_t>(std::stoi(match[1].str()));
      icmp_seq.max_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      icmp_seq.op = parseOperator(match[1].str());
      icmp_seq.min_value = static_cast<uint16_t>(std::stoi(match[2].str()));
    }

    nonpayload.icmp_seq = icmp_seq;
  }

  static void parseSEQOption(const std::string &value,
                             NonePayloadOption &nonpayload) {
    SEQ seq;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      seq.op = Operator::RANGE_INCLUSIVE;
      seq.min_value = static_cast<uint32_t>(std::stoi(match[1].str()));
      seq.max_value = static_cast<uint32_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      seq.op = parseOperator(match[1].str());
      seq.min_value = static_cast<uint32_t>(std::stoi(match[2].str()));
    }

    nonpayload.seq = seq;
  }

  static void parseACKOption(const std::string &value,
                             NonePayloadOption &nonpayload) {
    ACK ack;

    std::regex range_regex(R"(^(\d+)-(\d+)$)");
    std::regex operator_regex(R"(^([<>=!]*)(\d+)$)");
    std::smatch match;

    if (std::regex_match(value, match, range_regex)) {
      ack.op = Operator::RANGE_INCLUSIVE;
      ack.min_value = static_cast<uint32_t>(std::stoi(match[1].str()));
      ack.max_value = static_cast<uint32_t>(std::stoi(match[2].str()));
    } else if (std::regex_match(value, match, operator_regex)) {
      ack.op = parseOperator(match[1].str());
      ack.min_value = static_cast<uint32_t>(std::stoi(match[2].str()));
    }

    nonpayload.ack = ack;
  }
};

// Initialize static member
Buffer SnortRuleParser::current_buffer = Buffer::NONE;

// Helper function to print parsed rule for debugging
void printRule(const Rule &rule) {
  std::cout << "=== Rule Details ===" << std::endl;
  std::cout << "Action: " << rule.action.value_or("N/A") << std::endl;
  std::cout << "Protocol: " << rule.protocol.value_or("N/A") << std::endl;
  std::cout << "Source: " << rule.src_addr.value_or("N/A") << ":"
            << rule.src_port.value_or("N/A") << std::endl;
  std::cout << "Direction: " << rule.direction.value_or("N/A") << std::endl;
  std::cout << "Destination: " << rule.dst_addr.value_or("N/A") << ":"
            << rule.dst_port.value_or("N/A") << std::endl;

  if (rule.option.general.msg) {
    std::cout << "Message: " << *rule.option.general.msg << std::endl;
  }
  if (rule.option.general.gid) {
    std::cout << "GID: " << *rule.option.general.gid << std::endl;
  }
  std::cout << "SID: " << rule.option.general.sid << std::endl;
  std::cout << "ClassType: " << static_cast<int>(rule.option.general.classtype)
            << std::endl;

  if (rule.option.general.service) {
    std::cout << "Services: ";
    for (const auto &service : *rule.option.general.service) {
      std::cout << service << " ";
    }
    std::cout << std::endl;
  }

  if (!rule.option.payload.content.empty()) {
    std::cout << "Content patterns: " << rule.option.payload.content.size()
              << std::endl;
    for (size_t i = 0; i < rule.option.payload.content.size(); i++) {
      const auto &content = rule.option.payload.content[i];
      std::cout << "  [" << i << "] \"" << content.content << "\"";
      if (content.buffer != Buffer::NONE) {
        std::cout << " (buffer: " << static_cast<int>(content.buffer) << ")";
      }
      if (content.negate) {
        std::cout << " (negated)";
      }
      if (content.nocase) {
        std::cout << " (nocase)";
      }
      if (content.fast_pattern) {
        std::cout << " (fast_pattern)";
      }
      if (content.fast_pattern_only) {
        std::cout << " (fast_pattern_only)";
      }
      if (content.offset) {
        std::cout << " (offset: " << *content.offset << ")";
      }
      if (content.depth) {
        std::cout << " (depth: " << *content.depth << ")";
      }
      if (content.distance) {
        std::cout << " (distance: " << *content.distance << ")";
      }
      if (content.within) {
        std::cout << " (within: " << *content.within << ")";
      }
      std::cout << std::endl;
    }
  }

  if (rule.option.payload.pcre && !rule.option.payload.pcre->empty()) {
    std::cout << "PCRE patterns: " << rule.option.payload.pcre->size()
              << std::endl;
    for (size_t i = 0; i < rule.option.payload.pcre->size(); i++) {
      const auto &pcre = (*rule.option.payload.pcre)[i];
      std::cout << "  [" << i << "] " << pcre.pattern;
      if (pcre.negate)
        std::cout << " (negated)";
      if (pcre.i)
        std::cout << " (i)";
      if (pcre.s)
        std::cout << " (s)";
      if (pcre.m)
        std::cout << " (m)";
      std::cout << std::endl;
    }
  }

  if (rule.option.payload.dsize) {
    std::cout << "Data size check: ";
    switch (rule.option.payload.dsize->op) {
    case Operator::GREATER_THAN:
      std::cout << ">";
      break;
    case Operator::LESS_THAN:
      std::cout << "<";
      break;
    case Operator::EQUAL:
      std::cout << "=";
      break;
    case Operator::NOT_EQUAL:
      std::cout << "!=";
      break;
    case Operator::GREATER_EQUAL:
      std::cout << ">=";
      break;
    case Operator::LESS_EQUAL:
      std::cout << "<=";
      break;
    case Operator::RANGE_EXCLUSIVE:
      std::cout << "<>";
      break;
    case Operator::RANGE_INCLUSIVE:
      std::cout << "-";
      break;
    }
    std::cout << rule.option.payload.dsize->min_value;
    if (rule.option.payload.dsize->max_value) {
      if (rule.option.payload.dsize->op == Operator::RANGE_EXCLUSIVE) {
        std::cout << "<>" << *rule.option.payload.dsize->max_value;
      } else {
        std::cout << "-" << *rule.option.payload.dsize->max_value;
      }
    }
    std::cout << std::endl;
  }

  if (rule.option.payload.byte_tests &&
      !rule.option.payload.byte_tests->empty()) {
    std::cout << "Byte tests: " << rule.option.payload.byte_tests->size()
              << std::endl;
  }

  if (rule.option.payload.ber_data_list &&
      !rule.option.payload.ber_data_list->empty()) {
    std::cout << "BER data checks: "
              << rule.option.payload.ber_data_list->size() << std::endl;
  }

  if (rule.option.nonpayload.flow) {
    std::cout << "Flow option present" << std::endl;
  }

  if (rule.option.nonpayload.flags) {
    std::cout << "TCP flags check present" << std::endl;
  }

  if (rule.option.nonpayload.ttl) {
    std::cout << "TTL check: "
              << static_cast<int>(rule.option.nonpayload.ttl->min_value)
              << std::endl;
  }

  std::cout << "===================" << std::endl;
}

// Usage example function
void demonstrateParser(
    const std::string &rules_file = "./rule/snort3-community.rules") {
  try {
    std::cout << "Attempting to parse rules from: " << rules_file << std::endl;
    auto rules_map = SnortRuleParser::parseRulesFromFile(rules_file);

    int total_rules = 0;
    for (const auto &[protocol, rules] : rules_map) {
      total_rules += rules.size();
    }

    std::cout << "Successfully parsed " << total_rules << " rules from "
              << rules_file << std::endl;

    if (rules_map.empty()) {
      std::cout << "No rules were parsed. Check if the file exists and has "
                   "valid rules."
                << std::endl;
      return;
    }

    // Print statistics
    std::map<ClassType, int> classtype_counts;
    std::map<std::string, int> protocol_counts;
    int content_rules = 0;
    int pcre_rules = 0;
    int flow_rules = 0;

    for (const auto &[protocol, rules] : rules_map) {
      protocol_counts[protocol] = rules.size();

      for (const auto &rule : rules) {
        classtype_counts[rule.option.general.classtype]++;
        if (!rule.option.payload.content.empty()) {
          content_rules++;
        }
        if (rule.option.payload.pcre && !rule.option.payload.pcre->empty()) {
          pcre_rules++;
        }
        if (rule.option.nonpayload.flow) {
          flow_rules++;
        }
      }
    }

    std::cout << "\n=== Rule Statistics ===" << std::endl;
    std::cout << "Total rules: " << total_rules << std::endl;
    std::cout << "Rules with content: " << content_rules << std::endl;
    std::cout << "Rules with PCRE: " << pcre_rules << std::endl;
    std::cout << "Rules with flow: " << flow_rules << std::endl;

    std::cout << "\nProtocol distribution:" << std::endl;
    for (const auto &[protocol, count] : protocol_counts) {
      std::cout << "  " << protocol << ": " << count << std::endl;
    }

    std::cout << "\nClassType distribution (top 5):" << std::endl;
    std::vector<std::pair<int, ClassType>> sorted_classes;
    for (const auto &[classtype, count] : classtype_counts) {
      sorted_classes.push_back({count, classtype});
    }
    std::sort(sorted_classes.rbegin(), sorted_classes.rend());

    for (size_t i = 0; i < std::min(size_t(5), sorted_classes.size()); i++) {
      std::cout << "  ClassType " << static_cast<int>(sorted_classes[i].second)
                << ": " << sorted_classes[i].first << " rules" << std::endl;
    }

    // Print first few rules for demonstration
    std::cout << "\n=== Sample Rules ===" << std::endl;
    int count = 0;
    for (const auto &[protocol, rules] : rules_map) {
      for (const auto &rule : rules) {
        if (count >= 3)
          break;
        printRule(rule);
        count++;
      }
      if (count >= 3)
        break;
    }

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }
}

#endif