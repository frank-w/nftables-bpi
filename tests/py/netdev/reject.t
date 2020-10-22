:ingress;type filter hook ingress device lo priority 0

*netdev;test-netdev;ingress

reject with icmp type host-unreachable;ok;reject
reject with icmp type net-unreachable;ok;reject
reject with icmp type prot-unreachable;ok;reject
reject with icmp type port-unreachable;ok;reject
reject with icmp type net-prohibited;ok;reject
reject with icmp type host-prohibited;ok;reject
reject with icmp type admin-prohibited;ok;reject

reject with icmpv6 type no-route;ok;reject
reject with icmpv6 type admin-prohibited;ok;reject
reject with icmpv6 type addr-unreachable;ok;reject
reject with icmpv6 type port-unreachable;ok;reject
reject with icmpv6 type policy-fail;ok;reject
reject with icmpv6 type reject-route;ok;reject

reject;ok
