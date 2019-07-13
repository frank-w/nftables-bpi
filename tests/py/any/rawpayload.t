:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input
*netdev;test-netdev;ingress

meta l4proto { tcp, udp, sctp} @th,16,16 { 22, 23, 80 };ok;meta l4proto { 6, 17, 132} th dport { 22, 23, 80}
meta l4proto tcp @th,16,16 { 22, 23, 80};ok;tcp dport { 22, 23, 80}
@nh,8,8 255;ok
@nh,8,16 0;ok

# out of range (0-1)
@th,16,1 2;fail

@ll,0,0 2;fail
@ll,0,1;fail
@ll,0,1 1;ok;@ll,0,8 & 128 == 128
@ll,0,8 and 0x80 eq 0x80;ok;@ll,0,8 & 128 == 128
@ll,0,128 0xfedcba987654321001234567890abcde;ok;@ll,0,128 338770000845734292516042252062074518750
