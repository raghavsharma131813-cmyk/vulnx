#!/bin/bash
# Start the supporting services, then launch VulnX.
set -e

# SSH: VulnX connects to 127.0.0.1 as the "kali" user to run nmap,
# Metasploit, curl and openssl inside this container.
service ssh start

# Metasploit database (best effort; module discovery still works without it).
service postgresql start || true
msfdb init || true

echo "VulnX is starting on port ${VULNX_PORT:-5000} ..."
cd /app
exec python3 app.py
