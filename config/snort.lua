HOME_NET = '192.168.1.121/32'
EXTERNAL_NET = 'any'
DNS_SERVERS = HOME_NET
FTP_SERVERS = HOME_NET
HTTP_SERVERS = {'192.168.1.121'}
SMTP_SERVERS = HOME_NET
SIP_SERVERS = HOME_NET
SSH_SERVERS = HOME_NET
SQL_SERVERS = HOME_NET
TELNET_SERVERS = HOME_NET

HTTP_PORTS = '8080'  -- พอร์ตที่สนใจ

include 'snort_defaults.lua'

stream = {}; stream_tcp = {}; stream_udp = {}
http_inspect = { request_depth=-1, response_depth=-1, unzip=true, normalize_utf=true }
daq_module = 'afpacket'; daq_mode = 'passive'

ips = {
  mode = 'tap',
  enable_builtin_rules = false,
  variables = {
    nets = {
      HOME_NET       = HOME_NET,
      EXTERNAL_NET   = EXTERNAL_NET,
      DNS_SERVERS    = DNS_SERVERS,
      FTP_SERVERS    = FTP_SERVERS,
      HTTP_SERVERS   = HTTP_SERVERS,
      SIP_SERVERS    = SIP_SERVERS,
      SMTP_SERVERS   = SMTP_SERVERS,
      SQL_SERVERS    = SQL_SERVERS,
      SSH_SERVERS    = SSH_SERVERS,
      TELNET_SERVERS = TELNET_SERVERS
    },
    ports = {
      FTP_PORTS       = FTP_PORTS,
      HTTP_PORTS      = HTTP_PORTS,
      MAIL_PORTS      = MAIL_PORTS,
      ORACLE_PORTS    = ORACLE_PORTS,
      SIP_PORTS       = SIP_PORTS,
      SSH_PORTS       = SSH_PORTS,
      FILE_DATA_PORTS = FILE_DATA_PORTS
    }
  },
  include = '/home/fruitto/Project/HIPS/rules/snort3-community.rules'
}

loggers = {
  { name = 'alert_json', file=true,
    filename = '/home/fruitto/Project/HIPS/snort_logs/snort.alert',
    limit=100,
    fields='timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action msg class' }
}
pkt_logger = { file=true, limit=100 }

binder = {
  { when={ proto='tcp' }, use={ type='stream_tcp' } },
  { when={ proto='udp' }, use={ type='stream_udp' } },
  { when={ service='http' }, use={ type='http_inspect' } },
  { use={ type='wizard' } }
}
wizard = default_wizard
