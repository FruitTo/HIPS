include 'snort_defaults.lua'

-- Test config with wizard curses

stream = {}
stream_tcp = {}
stream_udp = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

variables = { HOME_NET = '127.0.0.1/32', EXTERNAL_NET = 'any' }

daq_module = 'pcap'
daq_mode = 'inline'

ips = { variables = default_variables, mode = 'inline', enable_builtin_rules = true }

loggers = {{ name='alert_json', file=true, filename='snort.alert' }}
pkt_logger = { file=true, limit=10 }

binder = {
  { when={ proto='tcp' }, use={ type='stream_tcp' } },
  { when={ proto='udp' }, use={ type='stream_udp' } },
  { use={ type='wizard' } }
}
