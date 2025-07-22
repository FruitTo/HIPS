include 'snort_defaults.lua'
wizard = default_wizard

stream = {}
stream_tcp = {}
stream_udp = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

HOME_NET = '192.168.1.121'
EXTERNAL_NET = '!192.168.1.121'

daq_module = 'afpacket'
daq_mode = 'passive'
ips = {
  include     = '/home/fruitto/Project/HIPS/rules/default.rules',
  mode        = 'tap',
  enable_builtin_rules = false,
  variables = {
    nets = {
      HOME_NET     = HOME_NET,
      EXTERNAL_NET = EXTERNAL_NET
    }
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
  { use={ type='wizard' } }
};
