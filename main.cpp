#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/filter.h"
#include "./include/flow_manager.h"
#include "./include/packet.h"
#include "./include/snort_rule.h"
#include "./include/snort_rule_parser.h"
#include "./include/header_detection.h"
#include "./include/tins/tins.h"

#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;
namespace fs = filesystem;


void parsePorts(const string &input, vector<string> &target);
void config(bool mode, const std::vector<std::pair<std::string, NetworkConfig>>& configuredInterfaces);
void sniff(const string &iface, auto &conf);
string join(const vector<string>& list, const string& sep);

auto rules = SnortRuleParser::parseRulesFromFile("./rules/snort3-community.rules");

int main()
{
  vector<string> interfaceName = getInterfaceName();
  vector<pair<string, NetworkConfig>> configuredInterfaces;
  thread_pool pool(interfaceName.size() + 1);
  vector<future<void>> task;

  bool mode;
  char modeInput;
  cout << "IPS Mode ? [y/n]" << endl;
  cin >> modeInput;
  mode = (modeInput == 'y' || modeInput == 'Y');

  // Config Interface
  for (const string &iface : interfaceName)
  {
    NetworkConfig conf;
    char yesno;
    string input;

    conf.NAME = iface;
    conf.IP = getIpInterface(iface);
    conf.HOME_NET = getIpInterface(iface);
    conf.EXTERNAL_NET = "!" + *conf.HOME_NET;

    cout << "\nConfiguring services for interface: " << iface << "\n";

    auto askService = [&](const string &name, optional<bool> &flag, vector<string> &ports)
    {
      cout << name << " Service? [y/n]: ";
      cin >> yesno;
      cin.ignore(numeric_limits<streamsize>::max(), '\n');
      bool enabled = (yesno == 'y' || yesno == 'Y');
      flag = enabled;
      if (enabled)
      {
        cout << "Enter " << name << " port(s) (space separated): ";
        getline(cin, input);
        parsePorts(input, ports);
      }
    };

    askService("HTTP", conf.HTTP_SERVERS, conf.HTTP_PORTS);
    askService("SSH", conf.SSH_SERVERS, conf.SSH_PORTS);
    askService("FTP", conf.FTP_SERVERS, conf.FTP_PORTS);
    askService("Oracle", conf.SQL_SERVERS, conf.ORACLE_PORTS);
    askService("FileData", conf.TELNET_SERVERS, conf.FILE_DATA_PORTS);
    askService("SMTP", conf.SMTP_SERVERS, conf.SMTP_PORTS);
    askService("TELNET", conf.TELNET_SERVERS, conf.TELNET_PORTS);

    // SIP
    cout << "SIP Service? [y/n]: ";
    cin >> yesno;
    cin.ignore();
    conf.SIP_SERVERS = (yesno == 'y' || yesno == 'Y');

    configuredInterfaces.emplace_back(iface, conf);
  }

  // Create Config File
  config(mode, configuredInterfaces);

  // Push Packet Capture Task
  for (auto &[iface, conf] : configuredInterfaces)
  {
    task.push_back(pool.submit_task([iface, conf]()
                                    { sniff(iface, conf); }));
  }

  // Push Create Subprocess Engine Task (Test Demo)
  task.push_back(pool.submit_task([&]()
                                  {
    // Create pipe
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("pipe failed");
        return;
    }

    // Fork process (if value > 0 : process ID; if value == 0 : process is startign)
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipe_fd[0], STDIN_FILENO);
        close(pipe_fd[1]);
        char *args[] = {
          (char *)"./snort.sh",
          // (char *)"-r", (char *)"-",
          (char *)"-A", (char *)"alert_fast",
          NULL
        };
        execvp("./snort.sh", args);

        perror("exec failed");
        _exit(1);
    }

    close(pipe_fd[0]); }));

  for (auto &t : task)
  {
    t.wait();
  }

  return 0;
}

void sniff(const string &iface, auto &conf)
{
  // Initial Flow Variable
  unordered_map<string, FlowEntry> flow_table;
  uint16_t bloom_counters[ARRAY_SIZE] = {0};
  uint64_t total_packets = 0;
  uint64_t total_flows = 0;
  auto last_cleanup = chrono::system_clock::now();

  // Initial Log Variable
  string currentDay = currentDate();
  string currentTime = timeStamp();
  string currentPath = getPath();
  filesystem::create_directories(currentPath);
  auto writer = make_unique<PacketWriter>(currentPath + iface + "_" + currentDay + "_" + currentTime + ".pcap", DataLinkType<EthernetII>());

  // Capture Packet (Sniffer)
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(iface, config);
  sniffer.sniff_loop([&](Packet &pkt)
                     {
        total_packets++;
        
        // Check Flow Time Expire
        auto now = chrono::system_clock::now();
        if (now - last_cleanup > chrono::minutes(1)) {
          cleanupExpiredFlows(flow_table);
          last_cleanup = now;
        }

        // Write logs
        string date = currentDate();
        string path = getPath();
        if (currentDay != date) {
          currentDay = date;
          currentPath = path;
          filesystem::create_directories(currentPath);
          writer = make_unique<PacketWriter>(currentPath + iface + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());
        }
        writer->write(pkt);
        
        // Filter
        PDU *pdu = pkt.pdu();
        if (pdu->find_pdu<IP>()) {
          IP &ip = pdu->rfind_pdu<IP>();
          PacketInfo packet;
          packet.protocol = "ip";
          IPFilter(&packet, ip);
          if (packet.src_addr == *conf.HOME_NET &&
              packet.dst_addr != *conf.HOME_NET) {
            packet.flow.direction = FlowDirection::TO_CLIENT;
          } else {
            packet.flow.direction = FlowDirection::TO_SERVER;
          }
          if (pdu->find_pdu<TCP>()) {
            TCP &tcp = pdu->rfind_pdu<TCP>();
            packet.protocol = "tcp";
            packet.tcp.emplace();
            TCPFilter(&packet, tcp);
            
            if (packet.tcp->payload_size > 0) {
              packet.flow.stream_mode = StreamMode::ONLY_STREAM;
            } else {
              packet.flow.stream_mode = StreamMode::NO_STREAM;
            }
            
            // HTTP Detection
            if (tcp.sport() == 80 || tcp.dport() == 80 || 
                tcp.sport() == 8080 || tcp.dport() == 8080 ||
                tcp.sport() == 443 || tcp.dport() == 443)  {
              packet.protocol = "http";
              packet.http.emplace();
              HTTPFilter(&packet, tcp);
            }
            
            // SSL/TLS Detection
            if (tcp.sport() == 443 || tcp.dport() == 443) {
              packet.ssl.emplace();
              SSLFilter(&packet, tcp);
            }
            
            // FTP Detection
            if (tcp.sport() == 21 || tcp.dport() == 21 || 
                tcp.sport() == 2021 || tcp.dport() == 2021) {
              packet.protocol = "ftp";
              packet.ftp.emplace();
              FTPFilter(&packet, tcp);
            }
            
            // SMTP Detection
            if (tcp.sport() == 25 || tcp.dport() == 25 ||
                tcp.sport() == 587 || tcp.dport() == 587 ||
                tcp.sport() == 465 || tcp.dport() == 465) {
              packet.protocol = "smtp";
              packet.smtp.emplace();
              SMTPFilter(&packet, tcp);
            }
            
            // DCE/RPC Detection
            if (tcp.sport() == 135 || tcp.dport() == 135) {
              packet.dce.emplace();
              DCEFilter(&packet, tcp);
            }
            
          } else if (pdu->find_pdu<UDP>()) {
            UDP &udp = pdu->rfind_pdu<UDP>();
            packet.protocol = "udp";
            packet.udp.emplace();
            UDPFilter(&packet, udp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
            
            // SIP Detection
            if (udp.sport() == 5060 || udp.dport() == 5060) {
              packet.protocol = "sip";
              packet.sip.emplace();
              SIPFilter(&packet, udp);
            }
            
          } else if (pdu->find_pdu<ICMP>()) {
            ICMP &icmp = pdu->rfind_pdu<ICMP>();
            packet.protocol = "icmp";
            packet.icmp.emplace();
            ICMPFilter(&packet, icmp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
          }
          
          // Flow
          size_t flows_before = flow_table.size();
          flowIdentication(&packet, &conf, flow_table, bloom_counters);
          if (flow_table.size() > flows_before) {
            total_flows++;
          }

          // Detection
          if(headerDetection(packet, rules, conf)){
            cout << "SRC : " << packet.src_addr << " -> DST : " << packet.dst_addr << endl;
          }
        }
        return true; });
}

void parsePorts(const string &input, vector<string> &target) {
    istringstream iss(input);
    string port;
    while (iss >> port)
        target.push_back(port);
}

string join(const vector<string>& list, const string& sep) {
    string out;
    for (size_t i = 0; i < list.size(); ++i) {
        out += list[i];
        if (i != list.size() - 1)
            out += sep;
    }
    return out;
}

void config(bool mode,
    const std::vector<std::pair<std::string, NetworkConfig>>& configuredInterfaces)
{
    namespace fs = std::filesystem;
    auto root  = fs::current_path();
    auto cfg   = root / "config" / "snort.lua";
    auto rules = root / "rules";
    auto logs  = root / "snort_logs";

    std::ofstream out(cfg);
    if (!out) return;

    out << "include 'snort_defaults.lua'\n\n-- auto-generated snort.lua\n\n";

    // 1) Inspector Modules: เปิดตาม service ที่ user เลือก
    out << "stream = {}\nstream_tcp = {}\nstream_udp = {}\n";
    bool need_http = false, need_ssh = false, need_ftp = false;
    bool need_smtp = false, need_telnet = false, need_sip = false;

    for (auto& [iface, nc] : configuredInterfaces) {
        need_http   |= nc.HTTP_SERVERS.value_or(false);
        need_ssh    |= nc.SSH_SERVERS.value_or(false);
        need_ftp    |= nc.FTP_SERVERS.value_or(false);
        need_smtp   |= nc.SMTP_SERVERS.value_or(false);
        need_telnet |= nc.TELNET_SERVERS.value_or(false);
        need_sip    |= nc.SIP_SERVERS.value_or(false);
    }
    if (need_http)   out << "http_inspect = {}\n";
    if (need_ssh)    out << "ssh = {}\n";
    if (need_ftp) {
        out << "ftp_server = {}\nftp_client = {}\nftp_data = {}\n";
    }
    if (need_smtp)   out << "smtp = {}\n";
    if (need_telnet) out << "telnet = {}\n";
    if (need_sip)    out << "sip = {}\n";
    out << "\n";

    // 2) Wizard setup สำหรับ autodetect
    out << "wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }\n\n";

    // 3) รวบรวม IPs และ ports จากทุก interface
    std::set<std::string> home_ips, ext_ips;
    std::set<std::string> http_ports, ssh_ports, ftp_ports, smtp_ports, telnet_ports;
    
    for (auto& [iface, nc] : configuredInterfaces) {
        home_ips.insert("'" + nc.IP + "'");
        ext_ips.insert("'!" + nc.IP + "'");

        http_ports.insert(nc.HTTP_PORTS.begin(), nc.HTTP_PORTS.end());
        ssh_ports.insert(nc.SSH_PORTS.begin(), nc.SSH_PORTS.end());
        ftp_ports.insert(nc.FTP_PORTS.begin(), nc.FTP_PORTS.end());
        // สมมติว่า NetworkConfig มี SMTP_PORTS และ TELNET_PORTS
        // ให้ผู้ใช้กรอกค่าพอร์ตเพิ่มเอง
        smtp_ports.insert(nc.SMTP_PORTS.begin(), nc.SMTP_PORTS.end());
        telnet_ports.insert(nc.TELNET_PORTS.begin(), nc.TELNET_PORTS.end());
    }

    auto join_set = [&](auto& s){
        std::ostringstream ss;
        bool first = true;
        for (auto& v : s) {
            if (!first) ss << " ";
            ss << v;
            first = false;
        }
        return ss.str();
    };
    auto join_list = [&](auto& s){
        std::ostringstream ss;
        bool first = true;
        for (auto& v : s) {
            if (!first) ss << ", ";
            ss << v;
            first = false;
        }
        return ss.str();
    };

    // 4) ประกาศ ports และ servers
    if (need_http) {
        out << "HTTP_SERVERS = { " << join_list(home_ips) << " }\n"
            << "HTTP_PORTS = '" << join_set(http_ports) << "'\n";
    }
    if (need_ssh) {
        out << "SSH_SERVERS = { " << join_list(home_ips) << " }\n"
            << "SSH_PORTS = '" << join_set(ssh_ports) << "'\n";
    }
    if (need_ftp) {
        out << "FTP_SERVERS = { " << join_list(home_ips) << " }\n"
            << "FTP_PORTS = '" << join_set(ftp_ports) << "'\n";
    }
    if (need_smtp) {
        out << "SMTP_SERVERS = { " << join_list(home_ips) << " }\n"
            << "SMTP_PORTS = '" << join_set(smtp_ports) << "'\n";
    }
    if (need_telnet) {
        out << "TELNET_SERVERS = { " << join_list(home_ips) << " }\n"
            << "TELNET_PORTS = '" << join_set(telnet_ports) << "'\n";
    }
    out << "\n";

    // 5) HOME_NET / EXTERNAL_NET
    out << "variables = {\n"
        << "  HOME_NET = { " << join_list(home_ips) << " },\n"
        << "  EXTERNAL_NET = { " << join_list(ext_ips) << " }\n}\n\n";

    // 6) DAQ/IPS
    out << "daq_module = 'af_packet'\n"
           "daq_mode = '" << (mode ? "inline" : "passive") << "'\n\n"
           "ips = {\n"
           "  variables = default_variables,\n"
           "  rules     = '" << rules.string() << "/snort3-community.rules',\n"
           "  mode      = '" << (mode ? "inline" : "tap") << "',\n"
           "  enable_builtin_rules = true\n"
           "}\n\n";

    // 7) Loggers
    out << "loggers = {{ name='alert_json', file=true, filename='"
           << logs.string() << "/snort.alert' }}\n\n"
        << "pkt_logger = { file=true, limit=1000 }\n\n";

    // 8) Binder
    out << "binder = {\n"
           "  { when={ proto='tcp' }, use={ type='stream_tcp' } },\n"
           "  { when={ proto='udp' }, use={ type='stream_udp' } },\n";
    if (need_http)   out << "  { when={ service='http' }, use={ type='http_inspect' } },\n";
    if (need_ssh)    out << "  { when={ service='ssh'  }, use={ type='ssh' } },\n";
    if (need_ftp)    out << "  { when={ service='ftp'  }, use={ type='ftp_server' } },\n";
    if (need_smtp)   out << "  { when={ service='smtp' }, use={ type='smtp' } },\n";
    if (need_telnet) out << "  { when={ service='telnet' }, use={ type='telnet' } },\n";
    if (need_sip)    out << "  { when={ service='sip' }, use={ type='sip' } },\n";
    out << "  { use={ type='wizard' } }\n"
           "}\n";

    out.close();
}
