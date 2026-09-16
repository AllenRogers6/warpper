#!/usr/bin/env bash
set -u
domain="${1:?usage: check-block.sh domain}"
proxy_port="${2:-15353}"

echo "1. proxy response"
answer=$(dig @127.0.0.1 -p "$proxy_port" "$domain" +short +time=2 +tries=1)
echo "  $domain → ${answer:-<no answer>}"

echo "2. system resolver response"
sys=$(dig "$domain" +short +time=2 +tries=1)
echo "  $domain → ${sys:-<no answer>}"

echo "3. connection test"
if curl -sS --max-time 5 -o /dev/null "https://$domain" 2>/dev/null; then
  echo "  CONNECTED — not blocked (or bypassing DNS)"
  exit 1
else
  rc=$?
  echo "  connection failed (curl exit $rc) — blocked"
fi

echo "4. audit log"
sqlite3 "${WARPPER_DB:-data/warpper.db}" \
  "SELECT timestamp, client, domain, action, rule_id
   FROM query_log WHERE domain='$domain'
   ORDER BY id DESC LIMIT 3;"
