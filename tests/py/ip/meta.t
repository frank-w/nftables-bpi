:input;type filter hook input priority 0

*ip;test-ip4;input

icmp type echo-request;ok
meta l4proto icmp icmp type echo-request;ok;icmp type echo-request
meta l4proto ipv6-icmp icmpv6 type nd-router-advert;ok;icmpv6 type nd-router-advert
meta l4proto 58 icmpv6 type nd-router-advert;ok;icmpv6 type nd-router-advert
icmpv6 type nd-router-advert;ok

meta ibrname "br0";fail
meta obrname "br0";fail
