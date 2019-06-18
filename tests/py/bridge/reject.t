:input;type filter hook input priority 0

*bridge;test-bridge;input

# The output is specific for bridge family
reject with icmp type host-unreachable;ok
reject with icmp type net-unreachable;ok
reject with icmp type prot-unreachable;ok
reject with icmp type port-unreachable;ok
reject with icmp type net-prohibited;ok
reject with icmp type host-prohibited;ok
reject with icmp type admin-prohibited;ok

reject with icmpv6 type no-route;ok
reject with icmpv6 type admin-prohibited;ok
reject with icmpv6 type addr-unreachable;ok
reject with icmpv6 type port-unreachable;ok

mark 12345 ip protocol tcp reject with tcp reset;ok;meta mark 0x00003039 ip protocol 6 reject with tcp reset

reject;ok
ether type ip reject;ok;reject with icmp type port-unreachable
ether type ip6 reject;ok;reject with icmpv6 type port-unreachable

reject with icmpx type host-unreachable;ok
reject with icmpx type no-route;ok
reject with icmpx type admin-prohibited;ok
reject with icmpx type port-unreachable;ok;reject

ether type ipv6 reject with icmp type host-unreachable;fail
ether type ip6 reject with icmp type host-unreachable;fail
ether type ip reject with icmpv6 type no-route;fail
ether type vlan reject;fail
ether type arp reject;fail
ether type vlan reject;fail
ether type arp reject;fail
ether type vlan reject with tcp reset;fail
ether type arp reject with tcp reset;fail
ip protocol udp reject with tcp reset;fail

ether type ip reject with icmpx type admin-prohibited;ok
ether type ip6 reject with icmpx type admin-prohibited;ok
ether type vlan reject with icmpx type admin-prohibited;fail
ether type arp reject with icmpx type admin-prohibited;fail
