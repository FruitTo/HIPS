include 'snort_defaults.lua'

-- Snort++ auto-generated configuration

variables = {
  HOME_NET = {'192.168.1.121', '127.0.0.1'},
  EXTERNAL_NET = {'!192.168.1.121', '!127.0.0.1'}
}

daq_module = 'af_packet'
daq_mode = 'inline'

ips = {
  rules = '/home/fruitto/Project/HIPS/rules/snort3-community.rules',
  mode = 'inline',
  enable_builtin_rules = true
}

loggers = {
  {
    name = 'alert_json',
    file = true,
    filename = '/home/fruitto/Project/HIPS/snort_logs/snort.alert'
  }
}

pkt_logger = {
  file = true,
  limit = 1000
}
