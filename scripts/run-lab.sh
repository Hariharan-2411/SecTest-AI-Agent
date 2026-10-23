#!/usr/bin/env bash
# Live E2E against the local Juice Shop lab. Requires: images built, LLM_API_KEY
# set in .env. Brings up lab+agent+orchestrator, runs an engagement, surfaces the
# approval, approves it, and prints findings.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
DT="${DASHBOARD_TOKEN:-}"
H=(-H "content-type: application/json" -H "x-dashboard-token: $DT")

echo "▶ bringing up lab + agent + orchestrator (destructive tier ON for the lab)…"
AGENT_ALLOW_DESTRUCTIVE=true docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build

echo "▶ waiting for orchestrator health…"
for i in $(seq 1 60); do curl -sf localhost:8790/health >/dev/null 2>&1 && break || sleep 2; done
curl -s localhost:8790/health; echo

echo "▶ submitting engagement (scope=juiceshop, seed=http://juiceshop:3000, destructive opt-in)…"
curl -s "${H[@]}" -X POST localhost:8790/api/engagements -d '{
  "name":"juiceshop-lab",
  "urls":["http://juiceshop:3000"],
  "rulesText":"This is my own lab. Automated scanning is allowed. Automated testing permitted.",
  "confirmed":true,
  "allowDestructive":true
}' | sed 's/.*/  &/'
echo

echo "▶ watching for approvals (auto-approving to simulate your tap)…"
for i in $(seq 1 90); do
  PEND=$(curl -s "${H[@]}" localhost:8790/api/approvals | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const a=JSON.parse(s||"[]").filter(x=>x.status==="pending");console.log(a.map(x=>x.id+"|"+x.call.tool+"@"+x.call.target).join("\n"))})')
  if [ -n "$PEND" ]; then
    echo "$PEND" | while IFS='|' read -r id rest; do
      [ -n "$id" ] && echo "  approving $rest" && curl -s "${H[@]}" -X POST "localhost:8790/api/approvals/$id/approve" >/dev/null
    done
  fi
  sleep 2
done &
WATCH=$!
sleep 120; kill $WATCH 2>/dev/null || true

echo "▶ runs:";     curl -s "${H[@]}" localhost:8790/api/runs     | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s),null,2)))'
echo "▶ findings:"; curl -s "${H[@]}" localhost:8790/api/findings | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s),null,2)))'
