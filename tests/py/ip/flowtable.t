:input;type filter hook input priority 0

*ip;test-ip;input

meter name xyz { ip saddr timeout 30s counter};ok
