-- Snort++ (Snort 3) Basic Configuration
-- Base: /home/fruitto/Project/engine

RULE_PATH = '/home/fruitto/Project/engine/rules'
LOG_PATH  = '/home/fruitto/Project/engine/snort_logs'
INTERFACE = 'enp2s0'

ipvar = {
    HOME_NET     = 'any',
    EXTERNAL_NET = 'any',
}

decoder = {}
stream = {}
stream_ip = {}
stream_tcp = {}
stream_udp = {}
stream_icmp = {}

detection = {}

-- ✅ Logging via alert_fast
loggers = {
    {
        name = 'alert_fast',
        file = true,
        filename = LOG_PATH .. '/snort.alert'
    }
}

-- Optional: packet logger
pkt_logger = {
    file = true,
    limit = 1000
}

-- ✅ Rules
ips = {
    rules = RULE_PATH .. '/snort3-community.rules'
}
