:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input

meta nfproto ipv4;ok
meta nfproto ipv6;ok
meta nfproto {ipv4, ipv6};ok
meta nfproto != {ipv4, ipv6};ok
meta nfproto ipv6 tcp dport 22;ok
meta nfproto ipv4 tcp dport 22;ok
meta nfproto ipv4 ip saddr 1.2.3.4;ok;ip saddr 1.2.3.4
meta nfproto ipv6 meta l4proto tcp;ok;meta nfproto ipv6 meta l4proto 6
meta nfproto ipv4 counter ip saddr 1.2.3.4;ok
meta ipsec exists;ok
meta secpath missing;ok;meta ipsec missing
meta ibrname "br0";fail
meta obrname "br0";fail
