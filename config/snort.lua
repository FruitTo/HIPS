include 'snort_defaults.lua'
wizard = default_wizard

http_inspect = {
  request_depth = -1,
  response_depth = -1,
  unzip = true,
  normalize_utf = true
}

HTTP_SERVERS = { '192.168.1.121' }
HTTP_PORTS = '8080'
FILE_DATA_PORTS = '25'
FTP_PORTS = '21'
ORACLE_PORTS = '1521'
SIP_PORTS = '5060'
SSH_PORTS = '22'
HOME_NET = '192.168.1.121'
EXTERNAL_NET = '!192.168.1.121'

stream = {}
stream_tcp = {}
stream_udp = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

daq_module = 'afpacket'
daq_mode = 'inline'
ips = {
  rules = [[
    include /home/fruitto/Project/HIPS/rules/default.rules
    include /home/fruitto/Project/HIPS/rules/http.rules
    include /home/fruitto/Project/HIPS/rules/telnet.rules
    include /home/fruitto/Project/HIPS/rules/sql.rules
    include /home/fruitto/Project/HIPS/rules/sip.rules
    include /home/fruitto/Project/HIPS/rules/smtp.rules
    include /home/fruitto/Project/HIPS/rules/ssh.rules
    include /home/fruitto/Project/HIPS/rules/ftp.rules
  ]],
  mode = 'inline',
  enable_builtin_rules = false,
  variables = {
    nets = {
      HOME_NET     = HOME_NET,
      EXTERNAL_NET = EXTERNAL_NET,
      HTTP_SERVERS = HOME_NET,
      TELNET_SERVERS = HOME_NET,
      SQL_SERVERS = HOME_NET,
      SIP_SERVERS = HOME_NET,
      SMTP_SERVERS = HOME_NET,
    },
    ports = {
      HTTP_PORTS = HTTP_PORTS,
      FILE_DATA_PORTS = FILE_DATA_PORTS,
      FTP_PORTS = FTP_PORTS,
      ORACLE_PORTS = ORACLE_PORTS,
      SIP_PORTS = SIP_PORTS,
      SSH_PORTS = SSH_PORTS,
    },
  }
}

alert_json = {
    fields = 'seconds timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action msg class',
    file = true,
    limit = 100,
}

pkt_logger = { file=true, limit=1000 }

binder = {
  { when={ proto='tcp' }, use={ type='stream_tcp' } },
  { when={ proto='udp' }, use={ type='stream_udp' } },
  { when={ service='http' }, use={ type='http_inspect' } },
  { use={ type='wizard' } }
};
