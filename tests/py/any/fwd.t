:ingress;type filter hook ingress device lo priority 0

*netdev;test-netdev;ingress

fwd to "lo";ok
fwd to meta mark map { 0x00000001 : "lo", 0x00000002 : "lo"};ok

fwd ip to 192.168.2.200 device "lo";ok
