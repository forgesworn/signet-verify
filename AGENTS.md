# signet-verify

Browser SDK for privacy-preserving age verification and cross-device
Sign-in-with-Signet. Websites call `verifyAge()` to check a cryptographic
age credential from a user's Signet app, or use `waitForAuthResponse()`
directly for a cross-device sign-in flow over a Nostr relay. No personal
data is collected; the SDK ships both an ESM build and an IIFE build for
`<script>` tag use. `verifyAge()` is the listener only: the sender of its
response message is not part of this package (see Common Pitfalls).

## Build & Test

| Command | Purpose |
|---------|---------|
| `npm ci` | Install dependencies |
| `npm run build` | Clean, type-compile, and build the IIFE bundle |
| `npm run typecheck` | Type-check without emitting |
| `npm test` | Run the test suite (vitest) |

## Structure

```
src/signet-verify.ts   - the entire SDK (ESM source, also bundled to IIFE)
tests/                 - vitest tests (integration, wait-for-auth-response)
examples/               - standalone HTML example (cross-device login)
dist/                   - build output (git-ignored)
```

## Conventions

- Single source file (`src/signet-verify.ts`); keep additions there unless
  the file grows large enough to justify splitting.
- Canonical protocol types (`VerifyRequest`, `VerifyResponse`) come from
  `signet-protocol` and are imported with `import type` only, so the IIFE
  bundle carries no runtime dependency on it.
- `issuedAt` (unix seconds) anchors every cross-device wait, including
  retries; it must not be recomputed on restart.

## Key Files

| File | Purpose |
|------|---------|
| `src/signet-verify.ts` | `verifyAge`, `waitForAuthResponse`, and all exported types/constants |
| `examples/cross-device-login.html` | Worked cross-device sign-in example |
| `README.md` | Full API reference, error codes, age range values |

## Common Pitfalls

- Do not recompute `issuedAt` on a restarted wait: the relay query anchor
  depends on the original value, and a fresh one silently misses responses
  published while the page was backgrounded.
- `verifyAge` never connects to a relay: its modal receives the response on
  a `BroadcastChannel` (`signet-verify-<requestId>`) and its only network
  request is to the verification bot. `relayUrl` there is just a field in
  the request object. Only `waitForAuthResponse` talks to a relay.
- Nothing in this package posts the `signet-verify-response` message
  (`type`, `requestId`, `credential` as a signed kind-30470 event,
  `subjectPubkey`; the README has the full shape). `verifyAge` keeps the
  request ID private and the modal shows only a 40-character stub that stops
  before it, so a real user cannot reach `verified: true` without a
  same-origin sender of the integrator's own. Never write docs or examples
  that present `verifyAge` as working end to end on its own.
- `since` overrides `issuedAt` for the relay query anchor; only set it
  directly if you need to bypass the `issuedAt` derivation.
- The IIFE build must stay free of runtime dependencies beyond what
  esbuild bundles from `@noble/curves`, `@noble/hashes` and `nostr-tools`;
  `signet-protocol` types are compile-time only.
