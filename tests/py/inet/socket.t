:sockchain;type filter hook prerouting priority -150

*ip;sockip4;sockchain
*ip6;sockip6;sockchain
*inet;sockin;sockchain

socket transparent 0;ok
socket transparent 1;ok
socket transparent 2;fail
