#!/usr/bin/env bash
# tunnels.sh — open SSH tunnels from the hub host to each agent.
#
# Each agent stays bound to 127.0.0.1:3001 on its own server. This script
# forwards a distinct LOCAL port on the hub host to each agent's loopback, so
# the hub can reach them at http://127.0.0.1:<localPort> — the baseUrl values
# in servers.json. Nothing is exposed to the network.
#
# For production, prefer autossh (auto-reconnects) and/or a systemd unit per
# tunnel. This plain-ssh version is the simplest starting point.
#
# Usage: edit the AGENTS list below, then:  bash tunnels.sh
set -euo pipefail

# Format: "<localPort> <ssh-target>"  (ssh-target = user@host, honouring ~/.ssh/config)
AGENTS=(
  "4101 carlton@web-01.example.com"
  "4102 carlton@web-02.example.com"
  "4103 carlton@db-01.example.com"
)

# The port every agent listens on internally (backend BIND_ADDRESS:PORT).
AGENT_PORT="${AGENT_PORT:-3001}"

command -v autossh >/dev/null 2>&1 && SSH_BIN="autossh -M 0" || SSH_BIN="ssh"

echo "Opening ${#AGENTS[@]} tunnel(s) using: ${SSH_BIN}"
for entry in "${AGENTS[@]}"; do
  lport="${entry%% *}"
  target="${entry#* }"
  echo "  localhost:${lport}  ->  ${target}:127.0.0.1:${AGENT_PORT}"
  # -f background, -N no remote command, -o keepalive so dead links drop fast
  $SSH_BIN -f -N \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -L "127.0.0.1:${lport}:127.0.0.1:${AGENT_PORT}" "${target}"
done

echo "Tunnels up. Check with:  ss -tlnp | grep -E '410[0-9]'"
echo "Tear down with:          pkill -f 'ssh -f -N -L 127.0.0.1:410'"
