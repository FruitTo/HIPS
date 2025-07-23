#ifndef SNORT_RULE_H
#define SNORT_RULE_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "./dto.h"
#include "./payload.h"
#include "./none_payload.h"

struct GeneralOption
{
   std::optional<std::string> msg;
   std::optional<uint16_t> gid;
   uint16_t sid;
   ClassType classtype;
   std::optional<std::vector<std::string>> service;
};

struct RuleOption
{
   GeneralOption general;
   PayloadOption payload;
   NonePayloadOption nonpayload;
};

struct Rule
{
   std::optional<std::string> action;
   std::optional<std::string> protocol;
   std::optional<std::string> src_addr;
   std::optional<std::string> src_port;
   std::optional<std::string> direction;
   std::optional<std::string> dst_addr;
   std::optional<std::string> dst_port;
   RuleOption option;
};

#endif