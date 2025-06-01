#ifndef SNORT_RULE_H
#define SNORT_RULE_H

#include <string>
#include <optional>

struct NetworkConfig {
    std::optional<std::string> EXTERNAL_NET;
    std::optional<std::string> FILE_DATA_PORTS;
    std::optional<std::string> FTP_PORTS;
    std::optional<std::string> HOME_NET;
    std::optional<std::string> HTTP_PORTS;
    std::optional<std::string> HTTP_SERVERS;
    std::optional<std::string> ORACLE_PORTS;
    std::optional<std::string> SMTP_SERVERS;
    std::optional<std::string> SQL_SERVERS;
    std::optional<std::string> SSH_PORTS;
    std::optional<std::string> TELNET_SERVERS;
};

#endif