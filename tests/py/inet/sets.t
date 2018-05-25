:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input
*bridge;test-inet;input
*netdev;test-netdev;ingress

!set1 type ipv4_addr timeout 60s;ok
?set1 192.168.3.4 timeout 30s, 10.2.1.1;ok

!set2 type ipv6_addr timeout 23d23h59m59s;ok
?set2 dead::beef timeout 5s;ok

ip saddr @set1 drop;ok
ip saddr != @set2 drop;fail

ip6 daddr != @set2 accept;ok
ip6 daddr @set1 drop;fail
