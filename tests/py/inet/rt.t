:output;type filter hook output priority 0

*inet;test-inet;output

rt nexthop 192.168.0.1;fail
rt nexthop fd00::1;fail
meta nfproto ipv4 rt nexthop 192.168.0.1;ok
meta nfproto ipv6 rt nexthop fd00::1;ok

tcp option maxseg size set rt mtu;ok
