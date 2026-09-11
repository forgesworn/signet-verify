# Signet Verify — Age Verification SDK

Add privacy-preserving age verification to any website. One script tag, one function call. No personal data collected.

## Quick Start

```html
<script src="https://cdn.signet.forgesworn.dev/signet-verify.js"></script>
<script>
  document.getElementById('verify-btn').addEventListener('click', async () => {
    const result = await Signet.verifyAge('18+');
    if (result.verified) {
      // User is verified as 18+ by a confirmed professional
      console.log('Verified! Tier:', result.tier);
    } else {
      console.log('Not verified:', result.error);
    }
  });
</script>
<button id="verify-btn">Verify your age</button>
```

## How It Works

1. Website calls `Signet.verifyAge('18+')`
2. A modal appears with a QR code
3. User scans with their Signet app and approves
4. The app sends a cryptographic proof (no PII)
5. The SDK verifies the proof AND checks the verifier's professional registration
6. Returns the result — the user's app can be closed

## Verifier Trust

By default, the SDK checks the verifier's professional registration against public registers (GMC, SRA, TRA, etc.) via the Signet verification bot. This prevents fake professional rings from issuing accepted credentials.

- **Default:** `verified: true` only when the verifier is confirmed against a public register
- **Configurable:** websites can accept unconfirmed verifiers or point to their own verification bot
- **Decentralised:** the verification bot is open source — anyone can run their own

```javascript
// Default: safe — only confirmed verifiers pass
const result = await Signet.verifyAge('18+');

// Accept unconfirmed verifiers (less safe, more permissive)
const result = await Signet.verifyAge('18+', { acceptUnconfirmed: true });

// Use your own verification bot
const result = await Signet.verifyAge('18+', { verifierCheckUrl: 'https://my-bot.example.com' });

// Skip verifier checking entirely
const result = await Signet.verifyAge('18+', { verifierCheckUrl: null });
```

## Cross-device Sign-in-with-Signet

`verifyAge` wraps the same-device QR/modal flow. For a cross-device sign-in —
a consumer minting its own challenge, opening the auth URL or QR on one
device, and waiting on a relay for the response published from the user's
phone — use `waitForAuthResponse` directly:

```ts
import { waitForAuthResponse, AUTH_FRESHNESS_WINDOW_SEC } from 'signet-verify';

const result = await waitForAuthResponse({
  requestId,        // the challenge you put in the auth URL / QR
  relayUrl,
  sessionPrivKey,    // your ephemeral session keypair's private key
  expectedOrigin: location.origin,
});
```

### The sign-in deadline

A cross-device sign-in has exactly one deadline, and you should show it to the user.

```ts
import { waitForAuthResponse, AUTH_FRESHNESS_WINDOW_SEC } from 'signet-verify';

// Stamp this ONCE, when you mint the challenge and open the auth URL / show the QR.
const issuedAt = Math.floor(Date.now() / 1000);
const expiresAt = issuedAt + AUTH_FRESHNESS_WINDOW_SEC; // show a countdown to this

const result = await waitForAuthResponse({
  requestId: challenge,
  relayUrl,
  sessionPrivKey,
  expectedOrigin: location.origin,
  issuedAt,          // ← pass on EVERY call for this sign-in, retries included
  abortSignal,       // ← optional; cancels the wait and closes the subscription
});
```

**Pass `issuedAt` on every call, including a restart.** On mobile the page is
suspended the moment it hands off to the signer app. A wait restarted without the
anchor asks the relay only for responses newer than the restart — which silently
excludes the one published while you were backgrounded, and it is never asked for
again. This was a real, 100%-reproducible failure before 0.5.2.

**Distinguish the failures.** The rejection message (also on `err.code`) is:

| Code | Meaning | What to offer |
|---|---|---|
| `expired` | A valid response arrived, but outside the window — the user was too late | A fresh sign-in |
| `timeout` | Nothing arrived | A retry, anchored to the same `issuedAt` |
| `denied` | The user rejected the request | Nothing; respect it |
| `aborted` | You aborted via `abortSignal` | Nothing |
| `relay-error` | The socket failed | A retry, anchored to the same `issuedAt` |

**`since` is an escape hatch.** It sets the relay query anchor directly and takes
precedence over `issuedAt`. Prefer `issuedAt`, which derives it correctly.

## API

### `Signet.verifyAge(requiredAgeRange, options?)`

Returns `Promise<SignetVerifyResult>`

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `relayUrl` | `string` | `wss://relay.damus.io` | Relay URL for cross-device communication |
| `theme` | `'light' \| 'dark' \| 'auto'` | `'auto'` | Modal colour scheme |
| `timeout` | `number` | `120000` | Timeout in milliseconds |
| `verifierCheckUrl` | `string \| null` | `'https://verify.signet.forgesworn.dev'` | Verification bot URL. Set to `null` to skip. |
| `acceptUnconfirmed` | `boolean` | `false` | Accept credentials from unconfirmed verifiers |

**Result:**

| Field | Type | Description |
|-------|------|-------------|
| `verified` | `boolean` | `true` if credential valid, age range met, AND verifier confirmed (or `acceptUnconfirmed` is true) |
| `ageRange` | `string \| null` | Age range from the credential (e.g. `'18+'`) |
| `tier` | `number \| null` | Verification tier (1–4) |
| `entityType` | `string \| null` | `'natural_person'`, `'persona'`, etc. |
| `verifierPubkey` | `string \| null` | Professional keypair of the issuing verifier |
| `verifierConfirmed` | `boolean \| null` | Whether the verifier is confirmed against a public register. `null` if check unavailable. |
| `verifierMethod` | `'A' \| 'B' \| 'C' \| 'D' \| null` | How the verifier was confirmed: A=NIP-05 on body domain, B=body-issued, C=cross-verified, D=website |
| `issuedAt` | `number \| null` | Unix timestamp of credential issuance |
| `expiresAt` | `number \| null` | Unix timestamp of credential expiry |
| `error` | `string \| undefined` | Error code (see below) |

**Error codes:**

| Error | Meaning |
|-------|---------|
| `'cancelled'` | User cancelled the verification |
| `'timeout'` | Verification timed out (default: 2 minutes) |
| `'invalid-credential'` | Credential signature failed verification |
| `'age-range-not-met'` | Credential age range doesn't satisfy the requirement |
| `'verifier-not-confirmed'` | Verifier is not confirmed against a public register |
| `'verifier-check-unavailable'` | Verification bot unreachable (credential valid but verifier status unknown) |

## Age Range Values

| Value | Meaning |
|-------|---------|
| `'0-3'` | Ages 0–3 |
| `'4-7'` | Ages 4–7 |
| `'8-12'` | Ages 8–12 |
| `'13-17'` | Ages 13–17 |
| `'18+'` | Adult (18 and over) |

## Privacy

- No personal data is transmitted — only a cryptographic proof of age range
- No account creation required on the website
- No cookies beyond session management
- The proof is verified entirely in the browser — no server-side API calls needed
- Verifier check is a single GET request returning confirmed/not — no user data sent
- Compliant with GDPR, COPPA, UK Online Safety Act, France SREN law
