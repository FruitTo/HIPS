include 'snort_defaults.lua'

-- auto-generated snort.lua

wizard = default_wizard

stream = {}
stream_tcp = {}
stream_udp = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

variables = {
  HOME_NET = { '127.0.0.1' },
  EXTERNAL_NET = { '!127.0.0.1' }
}

daq_module = 'socket'
daq_mode = 'inline'
daq_var = { socket = './tmp/snort.sock'}

ips = {
  variables = default_variables,
  include     = '/home/fruitto/Project/HIPS/rules/test.rules',
  mode      = 'tap',
  enable_builtin_rules = false
}

loggers = {
  {
    name = 'alert_json',
    file = true,
    filename = '/home/fruitto/Project/HIPS/snort_logs/snort.alert',
    limit = 100,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action msg class'
  }
}

pkt_logger = { file=true, limit=1000 }

binder = {
  { when={ proto='tcp' }, use={ type='stream_tcp' } },
  { when={ proto='udp' }, use={ type='stream_udp' } },
  { use={ type='wizard' } }
};
