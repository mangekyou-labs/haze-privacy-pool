#!/bin/bash
# D8.2c — Apply compliance portal migrations and seed the dedicated auditor grant.
# Requires DATABASE_URL environment variable pointing to a Postgres instance.
#
# Usage:
#   DATABASE_URL=postgres://... ./haze/dev/setup-compliance-db.sh
#
# For Vercel/Render: set DATABASE_URL in the deployment environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MIGRATIONS_DIR="$SCRIPT_DIR/../dev/postgres/migrations"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL is not set." >&2
  echo "Usage: DATABASE_URL=postgres://... $0" >&2
  exit 1
fi

echo "[D8.2c] Applying migrations to: $(echo "$DATABASE_URL" | sed 's/:[^@]*@/:***@/')"

# Apply migrations in order
for migration in $(ls "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort); do
  echo "[D8.2c] Applying $(basename "$migration")..."
  psql "$DATABASE_URL" -f "$migration" 2>&1
done

# Seed the dedicated auditor grant
echo "[D8.2c] Seeding dedicated auditor grant..."
AUDITOR_ADDRESS="0x2222222222222222222222222222222222222222"
APP_ID="0x$(printf '%064x' 0xa11)"

psql "$DATABASE_URL" -c "
INSERT INTO haze_compliance_grants (grant_id, wallet, application_id, role, granted_fields, denied_fields, revoked, expires_at)
VALUES (
  decode('0000000000000000000000000000000000000000000000000000000000000001', 'hex'),
  decode('${AUDITOR_ADDRESS#0x}', 'hex'),
  decode('${APP_ID#0x}', 'hex'),
  'application-auditor',
  ARRAY['tx_hash', 'amount', 'asset', 'timestamp', 'policy_version'],
  ARRAY['user', 'counterparty'],
  false,
  now() + interval '365 days'
)
ON CONFLICT (grant_id) DO NOTHING;
" 2>&1

echo "[D8.2c] Migration complete."
echo "[D8.2c] Tables: haze_compliance_challenges, haze_compliance_sessions, haze_compliance_grants,"
echo "         haze_compliance_cases, haze_compliance_exports, haze_compliance_access_log"
echo "[D8.2c] Dedicated auditor grant seeded: 0x2222...2222 → application-auditor"
