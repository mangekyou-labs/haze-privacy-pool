# D8.2c/d Infrastructure Setup

## Canonical production origin

Use `https://haze-avax.vercel.app` for production D8 curls and SIWE. The permanent redirect sources
are `haze-mu-flax.vercel.app`, `haze.vercel.app`, `haze-finance.vercel.app`, and
`haze-pool.vercel.app`; preview deployment URLs are not redirected. The production environment
must contain `HAZE_COMPLIANCE_DOMAIN=haze-avax.vercel.app` after the canonical alias is assigned and
the production deployment is rebuilt.

## D8.2c — Postgres Migration & DATABASE_URL

The `CompliancePostgresStore` adapter is implemented in `haze/web/apps/haze/lib/compliance-postgres-store.ts`.
The factory in `haze/web/apps/haze/lib/compliance-store.ts` automatically uses Postgres when `DATABASE_URL` is set.

### Steps

1. **Provision a Postgres database** (Neon free tier recommended):
   - Go to https://neon.tech and create a project
   - Copy the connection string (format: `postgres://user:pass@host/dbname?sslmode=require`)

2. **Set DATABASE_URL on Vercel**:
   ```bash
   vercel env add DATABASE_URL production
   # Paste the Neon connection string
   ```

3. **Apply migrations**:
   ```bash
   DATABASE_URL="postgres://..." psql -f haze/dev/postgres/migrations/0001_init.sql
   DATABASE_URL="postgres://..." psql -f haze/dev/postgres/migrations/0002_ops.sql
   DATABASE_URL="postgres://..." psql -f haze/dev/postgres/migrations/0003_compliance_portal.sql
   ```

   Or use the setup script:
   ```bash
   DATABASE_URL="postgres://..." ./haze/dev/setup-compliance-db.sh
   ```

4. **Verify**:
   ```bash
   curl -s -X POST https://haze-avax.vercel.app/api/compliance/auth/challenge \
     -H "Content-Type: application/json" \
     -d '{"wallet":"0x2222222222222222222222222222222222222222","applicationId":"0x...0a11"}'
   # Should return a challenge with nonce
   ```

## D8.2d — Fuji Log Poller

The Fuji log poller module is in `haze/web/apps/haze/lib/fuji-log-poller.ts`.
It scans HazePool for PrivateTransaction withdrawal events and creates compliance cases.

### Deployment Options

**Option A: Separate Node.js service on Render (recommended)**
1. Create a new Render Web Service from the same repo
2. Set rootDir to `haze/web/apps/haze`
3. Build: `npm install && npx tsc`
4. Start: `node --experimental-strip-types lib/fuji-log-poller.ts`
5. Set environment: `DATABASE_URL`, `AVALANCHE_RPC_URL=https://api.avax-test.network/ext/bc/C/rpc`

**Option B: Sidecar in the Vercel deployment**
- Not recommended — Vercel serverless cannot run background processes

**Option C: Cron job on Render**
- Use Render Cron Jobs to poll every 15 seconds
- Less efficient but works on free tier

### Verification

After deployment, check the compliance cases endpoint:
```bash
# After a withdrawal is made on Fuji, wait for the poller to pick it up
curl -s -H "Cookie: haze_compliance_session=<token>" \
  https://haze-avax.vercel.app/api/compliance/cases
# Should show dynamically ingested cases
```
