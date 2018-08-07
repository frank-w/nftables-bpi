:osfchain;type filter hook input priority 0

*ip;osfip;osfchain
*ip6;osfip6;osfchain
*inet;osfinet;osfchain

osf name "Linux";ok
osf name "morethansixteenbytes";fail
osf name ;fail
osf name { "Windows", "MacOs" };ok
ct mark set osf name map { "Windows" : 0x00000001, "MacOs" : 0x00000002 };ok
