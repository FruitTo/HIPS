#ifndef SNORT_RULE_H
#define SNORT_RULE_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "./dto.h"
#include "./payload.h"
#include "./none_payload.h"

struct NetworkConfig {
   std::string NAME;
   std::string IP;

   std::optional<std::string> HOME_NET;
   std::optional<std::string> EXTERNAL_NET;

   std::vector<std::string> HTTP_PORTS;
   std::vector<std::string> SSH_PORTS;
   std::vector<std::string> FTP_PORTS;
   std::vector<std::string> SIP_PORTS;

   std::vector<std::string> ORACLE_PORTS;
   std::vector<std::string> FILE_DATA_PORTS;

   std::optional<bool> HTTP_SERVERS = false;
   std::optional<bool> SSH_SERVERS = false;
   std::optional<bool> FTP_SERVERS = false;

   std::optional<bool> TELNET_SERVERS = false;
   std::optional<bool> SMTP_SERVERS = false;
   std::optional<bool> SIP_SERVERS = false;
   std::optional<bool> SQL_SERVERS = false;
};

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