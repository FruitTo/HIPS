include 'snort_defaults.lua'

-- auto-generated snort.lua

stream = {}
stream_tcp = {}
stream_udp = {}
http_inspect = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

variables = {
  HOME_NET = {'192.168.1.121'},
  EXTERNAL_NET = {'!192.168.1.121'}
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
  { use={ type='wizard' } }
}
