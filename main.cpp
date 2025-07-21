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

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;
namespace fs = filesystem;

void parsePorts(const string &input, vector<string> &target);
void config(bool mode, const vector<NetworkConfig> &configuredInterfaces);
void sniff(NetworkConfig &conf);
string join(const vector<string> &list, const string &sep);

auto rules = SnortRuleParser::parseRulesFromFile("./rules/default.rules");

int main()
{
  vector<string> interfaceName = getInterfaceName();
  vector<NetworkConfig> configuredInterfaces;
  thread_pool pool(interfaceName.size());
  vector<future<void>> task;
  cout << "Rule:" << rules["tcp"].size() << endl;

  // Select Mode.
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

    configuredInterfaces.push_back(conf);
  }

  // Create Config File
  config(mode, configuredInterfaces);

  // Create Virtual Interface
  int ret = system("sudo ./virtual_interface.sh");
  if (ret != 0)
  {
    cerr << "Error :" << ret << "\n";
    return 1;
  }

  // Create Snort Process
  pid_t pid = fork();
  if (pid == 0)
  {
    char const *argv[] = {
        "ip", "netns", "exec", "ns2",
        "./snort.sh",
        "--snaplen", "65535",
        "-c", "./config/snort.lua",
        "-i", "veth1",
        "-l", "./snort_logs",
        "-A", "fast",
        "-v",
        nullptr};
    execvp(argv[0], const_cast<char *const *>(argv));
    perror("execvp failed");
    _exit(1);
  }

  for (NetworkConfig &conf : configuredInterfaces)
  {
    task.push_back(pool.submit_task([&conf]()
                                    { sniff(conf); }));
  }

  for (auto &t : task)
  {
    t.wait();
  }

  return 0;
}

void sniff(NetworkConfig &conf)
{
  PacketSender sender("veth0");

  // Initial Flow Variable
  static mutex mtx;
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
  auto writer = make_unique<PacketWriter>(currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap", DataLinkType<EthernetII>());

  // Capture Packet (Sniffer)
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, config);
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
          writer = make_unique<PacketWriter>(currentPath + conf.NAME + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());
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
            cout << "Forwarded" << endl;
            sender.send(*pdu);
            // auto buf = pkt.pdu()->serialize();
            // write(write_fd, buf.data(), buf.size());
          }
        }
        return true; });
}

void parsePorts(const string &input, vector<string> &target)
{
  istringstream iss(input);
  string port;
  while (iss >> port)
    target.push_back(port);
}

string join(const vector<string> &list, const string &sep)
{
  string out;
  for (size_t i = 0; i < list.size(); ++i)
  {
    out += list[i];
    if (i != list.size() - 1)
      out += sep;
  }
  return out;
}
void config(bool mode, const vector<NetworkConfig> &configuredInterfaces)
{
  namespace fs = filesystem;
  auto root = fs::current_path();
  auto cfg = root / "config" / "snort.lua";
  auto logs = root / "snort_logs";
  fs::create_directories(logs);

  ofstream out(cfg);
  if (!out) {
    std::cerr << "Failed to open " << cfg << " for writing.\n";
    return;
  }

  out << "include 'snort_defaults.lua'\n";
  out << "wizard = default_wizard\n\n";

  // HTTP
  set<string> home_ips;
  set<string> http_ports;
  bool need_http = false;

  for (const auto &nc : configuredInterfaces)
  {
    home_ips.insert("'" + nc.IP + "'");
    if (nc.HTTP_SERVERS.value_or(false))
    {
      need_http = true;
      http_ports.insert(nc.HTTP_PORTS.begin(), nc.HTTP_PORTS.end());
    }
  }

  if (need_http && !http_ports.empty())
  {
    out << "http_inspect = {\n"
           "  request_depth = -1,\n"
           "  response_depth = -1,\n"
           "  unzip = true,\n"
           "  normalize_utf = true\n"
           "}\n";

    ostringstream ip_list;
    bool first = true;
    for (const auto &ip : home_ips)
    {
      if (!first) ip_list << ", ";
      ip_list << ip;
      first = false;
    }
    out << "HTTP_SERVERS = { " << ip_list.str() << " }\n";

    ostringstream port_list;
    first = true;
    for (const auto &port : http_ports)
    {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "HTTP_PORTS = '" << port_list.str() << "'\n\n";
  }

  out << "stream = {}\nstream_tcp = {}\nstream_udp = {}\n";
  out << "\nwizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }\n\n";

  // HOME_NET
  if (home_ips.size() > 1)
  {
    out << "HOME_NET = { ";
    bool first = true;
    for (auto &ip : home_ips)
    {
      if (!first) out << ", ";
      out << ip;
      first = false;
    }
    out << " }\n";
  }
  else
  {
    if (!home_ips.empty()) {
      out << "HOME_NET = " << *home_ips.begin() << "\n";
    } else {
      out << "HOME_NET = 'any'\n";
    }
  }

  // EXTERNAL_NET
  if (home_ips.size() > 1)
  {
    out << "EXTERNAL_NET = { ";
    bool first = true;
    for (auto &ip : home_ips)
    {
      string raw_ip = ip.substr(1, ip.size() - 2);
      if (!first) out << ", ";
      out << "'!" << raw_ip << "'";
      first = false;
    }
    out << " }\n\n";
  }
  else
  {
    if (!home_ips.empty()) {
      string raw_ip = (*home_ips.begin()).substr(1, (*home_ips.begin()).size() - 2);
      out << "EXTERNAL_NET = '!" << raw_ip << "'\n\n";
    } else {
      out << "EXTERNAL_NET = 'any'\n\n";
    }
  }

  // DAQ
  out << "daq_module = 'afpacket'\n";
  out << "daq_mode = '" << (mode ? "inline" : "passive") << "'\n";

  // IPS block
  out << "ips = {\n"
      << "  include     = '" << (root / "rules" / "default.rules").string() << "',\n"
      << "  mode        = '" << (mode ? "inline" : "tap") << "',\n"
      << "  enable_builtin_rules = false,\n"
      << "  variables = {\n"
      // IP SERVER 
      << "    nets = {\n"
      << "      HOME_NET     = HOME_NET,\n"
      << "      EXTERNAL_NET = EXTERNAL_NET\n"
      << "    }\n"
      // PORT SERVER
      // << "    ports = {\n"
      // << "    }\n"
      << "  }\n"
      << "}\n\n";

  // Logging
  out << "loggers = {\n"
         "  {\n"
         "    name = 'alert_json',\n"
         "    file = true,\n"
         "    filename = '" << (logs / "snort.alert").string() << "',\n"
         "    limit = 100,\n"
         "    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action msg class'\n"
         "  }\n"
         "}\n\n";

  out << "pkt_logger = { file=true, limit=1000 }\n\n";

  // Binder
  out << "binder = {\n"
         "  { when={ proto='tcp' }, use={ type='stream_tcp' } },\n"
         "  { when={ proto='udp' }, use={ type='stream_udp' } },\n";
  if (need_http)
    out << "  { when={ service='http' }, use={ type='http_inspect' } },\n";
  out << "  { use={ type='wizard' } }\n};\n";

  out.close();
}
