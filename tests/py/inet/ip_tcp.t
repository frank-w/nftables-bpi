:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input
*bridge;test-bridge;input
*netdev;test-netdev;ingress

# must not remove ip dependency -- ONLY ipv4 packets should be matched
ip protocol tcp tcp dport 22;ok;ip protocol 6 tcp dport 22

# can remove it here, ip protocol is implied via saddr.
ip protocol tcp ip saddr 1.2.3.4 tcp dport 22;ok;ip saddr 1.2.3.4 tcp dport 22

# but not here.
ip protocol tcp counter ip saddr 1.2.3.4 tcp dport 22;ok;ip protocol 6 counter ip saddr 1.2.3.4 tcp dport 22

# or here.
ip protocol tcp counter tcp dport 22;ok;ip protocol 6 counter tcp dport 22

ether type ip tcp dport 22;ok
