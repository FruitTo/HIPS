include 'snort_defaults.lua'

-- auto-generated snort.lua

stream = {}
stream_tcp = {}
stream_udp = {}
http_inspect = {}
ssh = {}
ftp_server = {}
ftp_client = {}
ftp_data = {}
smtp = {}
telnet = {}
sip = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

HTTP_SERVERS = { '127.0.0.1', '192.168.1.121' }
HTTP_PORTS = '8080 8888'
SSH_SERVERS = { '127.0.0.1', '192.168.1.121' }
SSH_PORTS = '1111 1112'
FTP_SERVERS = { '127.0.0.1', '192.168.1.121' }
FTP_PORTS = '2222 2223'
SMTP_SERVERS = { '127.0.0.1', '192.168.1.121' }
SMTP_PORTS = '6667 y'
TELNET_SERVERS = { '127.0.0.1', '192.168.1.121' }
TELNET_PORTS = '5555 7778'

variables = {
  HOME_NET = { '127.0.0.1', '192.168.1.121' },
  EXTERNAL_NET = { '!127.0.0.1', '!192.168.1.121' }
}

daq_module = 'af_packet'
daq_mode = 'inline'

ips = {
  variables = default_variables,
  rules     = '/home/fruitto/Project/HIPS/rules/snort3-community.rules',
  mode      = 'inline',
  enable_builtin_rules = true
}

loggers = {{ name='alert_json', file=true, filename='/home/fruitto/Project/HIPS/snort_logs/snort.alert' }}

pkt_logger = { file=true, limit=1000 }

binder = {
  { when={ proto='tcp' }, use={ type='stream_tcp' } },
  { when={ proto='udp' }, use={ type='stream_udp' } },
  { when={ service='http' }, use={ type='http_inspect' } },
  { when={ service='ssh'  }, use={ type='ssh' } },
  { when={ service='ftp'  }, use={ type='ftp_server' } },
  { when={ service='smtp' }, use={ type='smtp' } },
  { when={ service='telnet' }, use={ type='telnet' } },
  { when={ service='sip' }, use={ type='sip' } },
  { use={ type='wizard' } }
}
