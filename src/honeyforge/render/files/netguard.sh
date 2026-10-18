#!/bin/sh
# Owns the honeypot's network namespace. Applies a default-deny OUTPUT policy (replies to
# inbound connections still flow via conntrack), then drops every privilege and idles.
# The decoy joins this namespace with zero capabilities, so it cannot alter the rules.
set -eu

apply() {
  cmd="$1"
  "$cmd" -P OUTPUT DROP
  "$cmd" -F OUTPUT
  "$cmd" -A OUTPUT -o lo -j ACCEPT
  "$cmd" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "$cmd" -A OUTPUT -j LOG --log-prefix "hf-egress-drop " --log-level 4 2>/dev/null || true
}

apply iptables
if ip6tables -L OUTPUT >/dev/null 2>&1; then
  apply ip6tables
fi
echo "netguard: egress default-deny applied"

exec setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all \
  sleep infinity
