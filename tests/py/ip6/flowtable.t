:input;type filter hook input priority 0

*ip6;test-ip6;input

meter name acct_out { meta iif . ip6 saddr timeout 600s counter };ok;meter name acct_out { iif . ip6 saddr timeout 10m counter}
meter name acct_out { ip6 saddr . meta iif timeout 600s counter };ok;meter name acct_out { ip6 saddr . iif timeout 10m counter}
