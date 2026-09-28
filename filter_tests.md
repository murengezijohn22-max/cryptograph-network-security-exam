# Firewall Filter Tests

Environment (edit to match your lab): server `192.168.20.10`, staff PC `192.168.10.20`, guest PC `192.168.30.50`, external/other host `203.0.113.7`. Service (from assessor): `tcp/22` – change `SERVICE_PORT` in `firewall/firewall_rules.sh` if different.

Setup on the server: `sudo ./firewall/firewall_rules.sh apply` then `sudo iptables -L RECORDS_FW -n -v --line-numbers` (save output to `evidence/iptables_after_apply.txt`).

| # | Type | From | Command | Expected | Actual result |
|---|------|------|---------|----------|---------------|
| 1 | Permitted | Staff PC | `nc -zv -w 5 192.168.20.10 22` | `succeeded` / connection open | **TO FILL: paste real output** |
| 2 | Blocked | Guest PC | `nc -zv -w 5 192.168.20.10 22` | Timeout (packets dropped) | **TO FILL** |
| 3 | Blocked | External host | `nc -zv -w 5 192.168.20.10 22` | Timeout (packets dropped) | **TO FILL** |

Verification on the server after the tests:
`sudo iptables -L RECORDS_FW -n -v` (packet counters for the DROP rules should have increased) and `sudo dmesg | grep FW-` (log entries `FW-GUEST-DROP` and `FW-SVC-DROP`).

> Replace every "TO FILL" with the exact terminal output from your lab run and add screenshots to `evidence/`. Do not submit unverified results.
