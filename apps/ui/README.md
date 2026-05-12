# Security Buddy — UI

Next.js 15 (App Router) frontend for the Security Buddy adversarial evaluation platform.

See the [repo root README](../../README.md) for full setup instructions.

## pnpm scripts

```bash
pnpm dev          # start dev server at http://localhost:3000
pnpm build        # production build
pnpm start        # start production server
pnpm lint         # eslint
pnpm typecheck    # tsc --noEmit
pnpm test         # vitest unit tests
pnpm test:e2e     # playwright e2e tests (requires running server)
```

## Required environment variables

Copy `.env.example` to `.env.local` and fill in all values. The server will
refuse to start if any required variable is missing.
