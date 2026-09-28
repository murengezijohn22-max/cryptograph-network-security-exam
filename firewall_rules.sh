#!/usr/bin/env bash
# Laboratory firewall for the student-records server (iptables, applied on the server).
# AUTHORISED LAB USE ONLY. Run as root:  sudo ./firewall_rules.sh apply | remove | show
#
# >>> Edit the variables below to match the lab and the service given by the assessor <<<
SERVER_IP="${SERVER_IP:-192.168.20.10}"      # student records server
GUEST_NET="${GUEST_NET:-192.168.30.0/24}"    # guest network
STAFF_NET="${STAFF_NET:-192.168.10.0/24}"    # authorised staff network
SERVICE_PORT="${SERVICE_PORT:-22}"           # service specified by assessor (e.g. 22 SSH, 443 HTTPS, 3306 MySQL)
PROTO="${PROTO:-tcp}"
CHAIN="RECORDS_FW"

apply() {
  iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
  # keep existing sessions and loopback working
  iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A "$CHAIN" -i lo -j ACCEPT
  # (a) block guest network -> records server (ALL ports; logged; listed first so nothing overrides it)
  iptables -A "$CHAIN" -s "$GUEST_NET" -j LOG --log-prefix "FW-GUEST-DROP: " --log-level 4
  iptables -A "$CHAIN" -s "$GUEST_NET" -j DROP
  # (b) permit authorised staff network -> the specified service only
  iptables -A "$CHAIN" -p "$PROTO" -s "$STAFF_NET" --dport "$SERVICE_PORT" -m conntrack --ctstate NEW -j ACCEPT
  # (c) block any other inbound access to that service (external hosts, unknown networks)
  iptables -A "$CHAIN" -p "$PROTO" --dport "$SERVICE_PORT" -j LOG --log-prefix "FW-SVC-DROP: " --log-level 4
  iptables -A "$CHAIN" -p "$PROTO" --dport "$SERVICE_PORT" -j DROP
  # hook chain into INPUT for traffic addressed to the server
  iptables -C INPUT -d "$SERVER_IP" -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -d "$SERVER_IP" -j "$CHAIN"
  echo "Rules applied."; show
}
remove() {
  iptables -D INPUT -d "$SERVER_IP" -j "$CHAIN" 2>/dev/null
  iptables -F "$CHAIN" 2>/dev/null; iptables -X "$CHAIN" 2>/dev/null
  echo "Rules removed."
}
show() { iptables -L "$CHAIN" -n -v --line-numbers; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
case "${1:-}" in apply) apply;; remove) remove;; show) show;; *) echo "usage: $0 apply|remove|show"; exit 1;; esac
