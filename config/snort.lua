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
HOME_NET = '192.168.1.121'
EXTERNAL_NET = '!192.168.1.121'

stream = {}
stream_tcp = {}
stream_udp = {}

wizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }

daq_module = 'afpacket'
daq_mode = 'passive'
ips = {
  rules = [[
    include /home/fruitto/Project/HIPS/rules/default.rules
    include /home/fruitto/Project/HIPS/rules/http.rules
  ]],
  mode = 'tap',
  enable_builtin_rules = false,
  variables = {
    nets = {
      HOME_NET     = HOME_NET,
      EXTERNAL_NET = EXTERNAL_NET,
      HTTP_SERVERS = HOME_NET,
    },
    ports = {
      HTTP_PORTS = HTTP_PORTS,
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
