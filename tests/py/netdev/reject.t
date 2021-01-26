:ingress;type filter hook ingress device lo priority 0

*netdev;test-netdev;ingress

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
reject with icmpv6 type policy-fail;ok
reject with icmpv6 type reject-route;ok

mark 12345 reject with tcp reset;ok;meta l4proto 6 meta mark 0x00003039 reject with tcp reset

reject;ok
meta protocol ip reject;ok;reject with icmp type port-unreachable
meta protocol ip6 reject;ok;reject with icmpv6 type port-unreachable

reject with icmpx type host-unreachable;ok
reject with icmpx type no-route;ok
reject with icmpx type admin-prohibited;ok
reject with icmpx type port-unreachable;ok;reject

meta protocol ip reject with icmp type host-unreachable;ok;reject with icmp type host-unreachable
meta protocol ip6 reject with icmpv6 type no-route;ok;reject with icmpv6 type no-route

meta protocol ip6 reject with icmp type host-unreachable;fail
meta protocol ip ip protocol icmp reject with icmpv6 type no-route;fail
meta protocol ip6 ip protocol icmp reject with icmp type host-unreachable;fail
meta l4proto udp reject with tcp reset;fail

meta protocol ip reject with icmpx type admin-prohibited;ok
meta protocol ip6 reject with icmpx type admin-prohibited;ok
