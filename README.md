# Signet Verify — Age Verification SDK

Add privacy-preserving age verification to any website. One script tag, one function call. No personal data collected.

## Install

```bash
npm install signet-verify
```

## Quick Start

Script tag (the IIFE bundle exposes `window.Signet`; the version is pinned, so change `0.7.1` to upgrade):

```html
<button id="verify-btn">Verify your age</button>
<script src="https://cdn.jsdelivr.net/npm/signet-verify@0.7.1/dist/signet-verify.iife.js"></script>
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
```

ESM (bundler, browser only, since `verifyAge` opens a modal):

```ts
import { verifyAge } from 'signet-verify';

const result = await verifyAge('18+');
if (!result.verified) console.log('Not verified:', result.error);
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

`verifyAge` resolves with a `SignetVerifyResult` and reports failures in `result.error` rather than rejecting. `waitForAuthResponse` resolves with a `SignetAuthResult` on success and rejects with an `Error` whose `message` and `code` are the failure code (see below). Their `timeout` options also differ: for `verifyAge` it is how long the modal waits before resolving with `error: 'timeout'`; for `waitForAuthResponse` it is an optional, earlier give-up.

`verifyAge` wraps the same-device QR/modal flow. For a cross-device sign-in,
a consumer minting its own challenge, opening the auth URL or QR on one
device, and waiting on a relay for the response published from the user's
phone, use `waitForAuthResponse` directly:

```ts
import { schnorr } from '@noble/curves/secp256k1.js'; // install @noble/curves yourself; the SDK does not re-export it
import { bytesToHex } from '@noble/hashes/utils.js';
import { waitForAuthResponse, DEFAULT_RELAY_URL } from 'signet-verify';

// 1. Ephemeral session keypair. The private key must be a 32-byte Uint8Array;
//    a hex string is rejected with `invalid-session-privkey`.
const sessionPrivKey = schnorr.utils.randomSecretKey();
const sessionPubkey = bytesToHex(schnorr.getPublicKey(sessionPrivKey));

// 2. The challenge: 32 random bytes as 64-character hex. This is the `requestId`.
const requestId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

// 3. Stamp this ONCE, when you mint the challenge and open the auth URL / show the QR.
const issuedAt = Math.floor(Date.now() / 1000);

// 4. The auth URL (render it as a QR code or a link). The parameters mirror
//    examples/cross-device-login.html; `relay` must match `relayUrl` below.
const signetAppUrl = 'https://signet-app.example'; // placeholder: your Signet app's origin
const authUrl = signetAppUrl + '/?' + new URLSearchParams({
  auth: '1',
  challenge: requestId,
  origin: location.origin,
  name: 'My Site',
  callback: location.origin + '/callback', // unused in relay mode, still required
  t: String(issuedAt),
  relay: DEFAULT_RELAY_URL,
  sessionPubkey,
}).toString();

// 5. Wait for the response. Call controller.abort() to cancel.
const controller = new AbortController();
const result = await waitForAuthResponse({
  requestId,
  relayUrl: DEFAULT_RELAY_URL,
  sessionPrivKey,
  expectedOrigin: location.origin,
  issuedAt,          // pass on EVERY call for this sign-in, including retries
  abortSignal: controller.signal,
});
```

### The sign-in deadline

A cross-device sign-in has exactly one deadline: `issuedAt + AUTH_FRESHNESS_WINDOW_SEC`.
`AUTH_FRESHNESS_WINDOW_SEC` is `300` seconds (5 minutes). Past that point, this library
stops listening and reports `expired`, so show a countdown to it.

```ts
import { AUTH_FRESHNESS_WINDOW_SEC } from 'signet-verify';

const expiresAt = issuedAt + AUTH_FRESHNESS_WINDOW_SEC; // unix seconds; count down to this
const secondsLeft = () => Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
```

The `timeout` option is in milliseconds. Leave it out when you pass `issuedAt`: the
wait then lasts until the deadline above.

**Pass `issuedAt` on every call, including a restart.** On mobile the page is
suspended the moment it hands off to the signer app. A wait restarted without the
anchor asks the relay only for responses newer than the restart — which silently
excludes the one published while you were backgrounded, and it is never asked for
again. This was a real, 100%-reproducible failure before 0.5.2.

**Distinguish the failures.** The rejection is an `Error` whose message is one of:

| Code | Meaning | What to offer |
|---|---|---|
| `expired` | This sign-in is over — its validity window ran out, or a response arrived too late | A fresh sign-in (new challenge, new `issuedAt`) |
| `timeout` | The wait gave up early — an explicit shorter `timeout`, or no `issuedAt` was supplied at all | A retry, anchored to the same `issuedAt` |
| `denied` | The user rejected the request | Nothing; respect it |
| `aborted` | You aborted via `abortSignal` | Nothing |
| `relay-error` | The socket failed. Rejected only where there is no `document` (a non-browser runtime); in a browser the wait reconnects while the page is visible and gives up with `timeout` or `expired` | A retry, anchored to the same `issuedAt` |
| `relay-closed` | The socket closed. Same rule as `relay-error` | A retry, anchored to the same `issuedAt` |
| `relay-refused` | The relay closed the subscription — `err.reason` has its text (e.g. `auth-required`) | A relay that serves gift wraps to an unauthenticated reader. `relay.damus.io` currently does not; `nos.lol` (the default) does |
| `invalid-issued-at` | `issuedAt` looks like the wrong unit (e.g. milliseconds) or is too far in the future | A bug in your code, not a retry; check you're passing unix **seconds** |
| `invalid-request-id`, `invalid-session-privkey`, `invalid-relay-url`, `invalid-expected-origin` | The matching option failed validation before any connection was made | A bug in your code, not a retry; see the option table below |

The code is on both `err.message` and `err.code` — branch on either.

**`since` is an escape hatch.** It sets the relay query anchor directly and takes
precedence over `issuedAt`. Prefer `issuedAt`, which derives it correctly.

## API

### `verifyAge(requiredAgeRange, options?)` (`Signet.verifyAge` in the IIFE build)

Returns `Promise<SignetVerifyResult>`. Failures are reported in `result.error`, not as a rejection.

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `relayUrl` | `string` | `DEFAULT_RELAY_URL` (`wss://nos.lol`) | Relay URL passed to the Signet app in the request. `verifyAge` itself does not connect to it. Must serve kind-1059 gift wraps to an unauthenticated reader |
| `theme` | `'light' \| 'dark' \| 'auto'` | `'auto'` | Modal colour scheme |
| `timeout` | `number` | `120000` | Timeout in milliseconds, clamped to 5000 to 600000 |
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
| `'invalid-age-range'` | `requiredAgeRange` is not one of the five values under Age Range Values; no modal is shown |
| `'invalid-credential'` | Credential signature failed verification |
| `'credential-expired'` | The credential's `expires` time has passed |
| `'age-range-not-met'` | Credential age range doesn't satisfy the requirement |
| `'verifier-not-confirmed'` | Verifier is not confirmed against a public register |
| `'verifier-check-unavailable'` | Verification bot unreachable (credential valid but verifier status unknown) |

### `waitForAuthResponse(options)` (`Signet.waitForAuthResponse` in the IIFE build)

Returns `Promise<SignetAuthResult>`. It resolves with the verified result and rejects with an `Error` on failure; `err.code` is one of the codes in the failure table under Cross-device Sign-in-with-Signet.

**Options (`WaitForAuthOptions`):**

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `requestId` | `string` | yes | none | The challenge sent in the auth URL: 64-character hex (32 bytes) |
| `relayUrl` | `string` | yes | none | The relay you subscribed on. `wss://`, or `ws://` for `localhost` and `127.0.0.1` only |
| `sessionPrivKey` | `Uint8Array` | yes | none | Ephemeral session private key, 32 bytes. Used to unwrap the NIP-17 response |
| `expectedOrigin` | `string` | yes | none | Your origin (scheme, host and optional port), verbatim. Must match the `origin` tag of the signed auth event |
| `issuedAt` | `number` | no, but pass it | none | Unix **seconds** when you minted the challenge. Anchors the relay query and the deadline. More than 300 seconds in the future rejects with `invalid-issued-at` |
| `timeout` | `number` | no | Remaining validity (`issuedAt + 300` seconds minus now) when `issuedAt` is set, otherwise `120000` | Milliseconds, clamped to 5000 to 600000. Use it only to give up earlier than the default |
| `since` | `number` | no | `issuedAt - 60` when `issuedAt` is set, otherwise now minus 60 | Raw relay query anchor in unix seconds. Takes precedence over `issuedAt` |
| `abortSignal` | `AbortSignal` | no | none | Aborts the wait and closes the subscription; rejects with `aborted` |

**Result (`SignetAuthResult`):**

| Field | Type | Description |
|-------|------|-------------|
| `pubkey` | `string` | The user's pubkey (64-character hex); a copy of `authEvent.pubkey` |
| `authEvent` | `SignetAuthEvent` | The verified, signed kind-21236 event: `id`, `pubkey`, `kind`, `created_at`, `tags`, `content`, `sig` |
| `credential` | `unknown` (optional) | Credential included in the response (Signet Login flows), passed through as received |
| `displayName` | `string` (optional) | Persona handle the user chose to share. Control and bidi characters are stripped and it is capped at 64 characters; still escape it when rendering |
| `bunkerUri` | `string` (optional) | A `bunker://` URI for upgrading to a live signer. Absent on auth-only flows |
| `createdAt` | `number` | Unix seconds at which the auth event was signed |

**Constants:** `AUTH_FRESHNESS_WINDOW_SEC` (`300`, seconds) and `DEFAULT_RELAY_URL` (`'wss://nos.lol'`).

## Age Range Values

| Value | Meaning |
|-------|---------|
| `'0-3'` | Ages 0–3 |
| `'4-7'` | Ages 4–7 |
| `'8-12'` | Ages 8–12 |
| `'13-17'` | Ages 13–17 |
| `'18+'` | Adult (18 and over) |

Matching is exact: the credential's age range must equal `requiredAgeRange`. An `'18+'` credential does not satisfy `'13-17'`, and a `'13-17'` credential does not satisfy `'18+'`. Any other `requiredAgeRange` is rejected: `verifyAge` resolves at once with `error: 'invalid-age-range'` and shows no modal.

## Privacy

- No personal data is transmitted — only a cryptographic proof of age range
- No account creation required on the website
- No cookies beyond session management
- Proof verification runs in the browser. `verifyAge` makes one network request, to the verification bot, unless `verifierCheckUrl` is `null`; `waitForAuthResponse` connects only to the relay you give it
- The verifier check is a single GET request that sends only the verifier's public key and returns confirmed or not
