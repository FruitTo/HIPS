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
   std::optional<std::string> HOME_NET;           
   std::optional<std::string> EXTERNAL_NET;
   std::vector<std::string> HTTP_PORTS = {"80","443","8080","8443"};
   std::vector<std::string> SSH_PORTS = {"22","2222"};  
   std::vector<std::string> FTP_PORTS = {"21","2021"};
   std::vector<std::string> ORACLE_PORTS = {"1521","1522"};
   std::vector<std::string> FILE_DATA_PORTS = {"143","993","110","995"}; 
   std::optional<bool> HTTP_SERVERS;       
   std::optional<bool> SMTP_SERVERS;       
   std::optional<bool> SQL_SERVERS;        
   std::optional<bool> TELNET_SERVERS;    
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