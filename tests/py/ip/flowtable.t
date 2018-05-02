:input;type filter hook input priority 0

*ip;test-ip;input

meter xyz { ip saddr timeout 30s counter};ok;meter xyz size 65535 { ip saddr timeout 30s counter}
