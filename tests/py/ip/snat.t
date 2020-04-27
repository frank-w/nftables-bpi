:postrouting;type nat hook postrouting priority 0

*ip;test-ip4;postrouting

iifname "eth0" tcp dport 80-90 snat to 192.168.3.2;ok
iifname "eth0" tcp dport != 80-90 snat to 192.168.3.2;ok
iifname "eth0" tcp dport {80, 90, 23} snat to 192.168.3.2;ok
iifname "eth0" tcp dport != {80, 90, 23} snat to 192.168.3.2;ok

iifname "eth0" tcp dport != 23-34 snat to 192.168.3.2;ok

snat ip addr . port to ip saddr map { 10.141.11.4 : 192.168.2.3 . 80 };ok
snat ip interval to ip saddr map { 10.141.11.4 : 192.168.2.2-192.168.2.4 };ok
snat ip prefix to ip saddr map { 10.141.11.0/24 : 192.168.2.0/24 };ok
