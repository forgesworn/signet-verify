# Signet Verify — Age Verification SDK

Add privacy-preserving age verification to any website. One script tag, one function call. No personal data collected.

`verifyAge` is the listening half of a same-browser exchange: it opens a modal and waits for a signed response message from a sender in the same origin. This package does not include that sender, and `verifyAge` does not hand the page the request ID the sender needs. See [What posts the response](#what-posts-the-response).

## Install

```bash
npm install signet-verify
```

## Quick Start

Script tag (the IIFE bundle exposes `window.Signet`; the URL pins a version, so change the version number in it to upgrade):

```html
<button id="verify-btn">Verify your age</button>
<script src="https://cdn.jsdelivr.net/npm/signet-verify@0.7.2/dist/signet-verify.iife.js"></script>
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

Both samples show the call and the result handling. `result.verified` becomes `true` only after a same-origin sender posts a valid `signet-verify-response` message for that call (see [The response message](#the-response-message)). Without one, the modal keeps waiting and the call resolves with `error: 'timeout'` after 120 seconds (the default `timeout`), or `error: 'cancelled'` if the user closes the modal.

### Node, SSR and tests

The package is ESM only and has no CommonJS build. Importing it in Node, during server-side rendering or in a test runner is safe: loading it touches no browser global, and it sets `window.Signet` only where a `window` exists. It needs Node 20.19 or later, the floor set by the `engines` fields of its `@noble/curves` and `@noble/hashes` dependencies.

- `verifyAge` is browser only. It needs `document`, `window.matchMedia`, `BroadcastChannel` and the `<dialog>` element. In Node it rejects with `ReferenceError: document is not defined` rather than resolving with `result.error`. The one exception is an invalid `requiredAgeRange`, which resolves with `error: 'invalid-age-range'` before touching the DOM. Call it from client-side code only, and stub it or use a real browser in tests.
- `waitForAuthResponse` needs no DOM, only a global `WebSocket`. Node 22 and later has one. Where there is none (Node 20, for example) the call rejects with `relay-error`. Outside a browser it never reconnects: the first socket error or close rejects with `relay-error` or `relay-closed`.

## How It Works

1. Website calls `Signet.verifyAge('18+')`
2. A modal opens. The SDK builds a `signet-verify-request` (request ID, required age range, `relayUrl`, timestamp) but the modal shows only a truncated text placeholder, `signet:verify:` plus the first 40 characters of the base64 payload, not a rendered QR code. Those 40 characters stop before the request ID and the relay URL
3. The modal listens on a `BroadcastChannel` named `signet-verify-<requestId>`. It opens no WebSocket and never reads from a relay. The proof must arrive as a `signet-verify-response` message carrying that request ID on that channel, so whatever posts it has to run in the same origin and browser profile as the page. Nothing in this package posts it (see below)
4. The SDK checks the credential's signature, expiry and age range, then asks the verification bot about the verifier's professional registration (skipped when `verifierCheckUrl` is `null`)
5. Returns the result

To receive a response from another device over a relay, use `waitForAuthResponse` (see below); `verifyAge` does not do that.

### What posts the response

Nothing in this package does. `signet-verify` contains the listener only, and the sender is code you provide, running in the same origin and browser profile as the page that called `verifyAge`.

The sender needs the channel name, which contains the request ID. `verifyAge` generates that ID internally and does not expose it: it is not returned, not passed to a callback and not dispatched as an event, and the modal shows only the first 40 characters of the base64 request, which stop before the ID. The package therefore offers no supported way for the page, or for a Signet app on the user's phone, to learn it. Until you have wired up a sender that can, a real user cannot reach `verified: true` through `verifyAge`.

### The response message

The listener accepts one object on the channel `signet-verify-<requestId>`, where `<requestId>` is the 32-character hex ID (16 random bytes) generated for that call. The shape is `VerifyResponse` from the `signet-protocol` package, which is the canonical type. Install `signet-protocol` only if you want that type for your sender: `signet-verify` does not depend on it at runtime, and its published type declarations do not reference it.

The shape:

```ts
{
  type: 'signet-verify-response',
  requestId: string,       // must equal the ID of the open modal
  credential: {            // a signed Nostr event
    id: string,            // 64 hex chars: SHA-256 of JSON [0, pubkey, created_at, kind, tags, content]
    kind: 30470,           // anything else is rejected
    pubkey: string,        // 64 hex chars: the verifier's key, returned as verifierPubkey
    created_at: number,    // unix seconds, returned as issuedAt
    tags: string[][],      // must include 'tier', 'age-range' and 'entity-type'; optional 'expires' (unix seconds)
    content: string,       // at most 65536 characters
    sig: string,           // 128 hex chars: BIP-340 Schnorr signature over id by pubkey
  },
  subjectPubkey: string,   // part of the protocol type; verifyAge does not read it
}
```

How the listener treats a message:

- It silently drops anything that is not an object, whose `type` or `requestId` does not match, or whose `credential` is missing or has no `tags` array. The modal keeps waiting.
- Any other message closes the modal and settles the call, so the first one wins and later messages are ignored. The credential is then checked: a failed structural or signature check (including more than 100 tags, a tag value over 1024 characters, or a missing `tier`, `age-range` or `entity-type` tag) gives `invalid-credential`, a past `expires` gives `credential-expired`, and an `age-range` tag that is not equal to the required range gives `age-range-not-met`. The verifier check then follows, as described under Verifier Trust.

## Verifier Trust

By default, the SDK checks the verifier's professional registration against public registers (GMC, SRA, TRA, etc.) via the Signet verification bot. This prevents fake professional rings from issuing accepted credentials.

- **Default:** `verified: true` only when the verifier is confirmed against a public register
- **Configurable:** websites can accept unconfirmed verifiers or point to their own verification bot
- **Decentralised:** the verification bot is open source — anyone can run their own

```javascript
// Default: safe, only confirmed verifiers pass
const strict = await Signet.verifyAge('18+');

// Accept unconfirmed verifiers (less safe, more permissive)
const lenient = await Signet.verifyAge('18+', { acceptUnconfirmed: true });

// Use your own verification bot
const ownBot = await Signet.verifyAge('18+', { verifierCheckUrl: 'https://my-bot.example.com' });

// Skip the verifier check. On its own this never verifies: the result is
// `verified: false` with `error: 'verifier-check-unavailable'`.
// To accept the credential without a check, also set acceptUnconfirmed.
const unchecked = await Signet.verifyAge('18+', { verifierCheckUrl: null, acceptUnconfirmed: true });
```

### What `verified` is when the check is skipped or fails

The credential must first be valid, unexpired and in the required age range. The table then shows how the verifier check decides `verified`:

| Verifier check | `verifierConfirmed` | Default (`acceptUnconfirmed: false`) | `acceptUnconfirmed: true` |
|---|---|---|---|
| Bot says confirmed | `true` | `verified: true` | `verified: true` |
| Bot says not confirmed | `false` | `verified: false`, `verifier-not-confirmed` | `verified: true`, no error |
| Skipped or failed | `null` | `verified: false`, `verifier-check-unavailable` | `verified: true`, no error |

The check counts as skipped when `verifierCheckUrl` is `null`, and as failed when the URL does not start with `https://`, the bot is unreachable or does not answer within 5 seconds, it returns a non-2xx status, or the body is not JSON. With `acceptUnconfirmed: true` the bot is still queried (unless `verifierCheckUrl` is `null`), so `verifierConfirmed` is still reported.

When the check is skipped, or `acceptUnconfirmed` is `true`, `verified: true` means only that a well-formed credential signed by some key meets the age range. It does not show that the signing key belongs to a registered professional.

## Cross-device Sign-in-with-Signet

`verifyAge` resolves with a `SignetVerifyResult` and reports failures in `result.error` rather than rejecting. `waitForAuthResponse` resolves with a `SignetAuthResult` on success and rejects with an `Error` whose `message` and `code` are the failure code (see below). Their `timeout` options also differ: for `verifyAge` it is how long the modal waits before resolving with `error: 'timeout'`; for `waitForAuthResponse` it is an optional, earlier give-up.

`verifyAge` is the same-browser modal flow: its response arrives on a
`BroadcastChannel`, never over a relay. For a cross-device sign-in,
a consumer minting its own challenge, opening the auth URL or QR on one
device, and waiting on a relay for the response published from the user's
phone, use `waitForAuthResponse` directly.

The example below imports `@noble/curves` and `@noble/hashes` itself. Both are dependencies of `signet-verify`, but the SDK does not re-export them, so install the ones your code imports (version 2 of each: in `@noble/curves` 2 the key generator is `schnorr.utils.randomSecretKey()`, and `randomPrivateKey()` no longer exists):

```bash
npm install signet-verify @noble/curves@2 @noble/hashes@2
```

```ts
import { schnorr } from '@noble/curves/secp256k1.js';
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
//    examples/cross-device-login.html; `relay` must match `relayUrl` below. The
//    Signet app README documents them: `origin` is https (or http://localhost),
//    `callback` is on that origin, `t` is within 300 seconds of the phone's
//    clock, and `relay` and `sessionPubkey` go together.
const signetAppUrl = 'https://mysignet.app'; // the Signet app's production origin (its dev server is https://localhost:5174)
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
| `relay-error` | The socket failed. Rejected only where there is no `document` (a non-browser runtime); in a browser the wait reconnects while the page is visible and gives up with `timeout` or `expired`. A runtime with no global `WebSocket` (Node 20, for example) gets it at once; see Node, SSR and tests | A retry, anchored to the same `issuedAt` |
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
| `relayUrl` | `string` | `DEFAULT_RELAY_URL` (`wss://nos.lol`) | Written into the `relayUrl` field of the request object `verifyAge` builds. `verifyAge` never connects to it, the response does not travel over it (it arrives on a `BroadcastChannel`), and the text the modal shows does not include it. The kind-1059 gift-wrap requirement under `waitForAuthResponse` therefore does not apply to this option |
| `theme` | `'light' \| 'dark' \| 'auto'` | `'auto'` | Modal colour scheme |
| `timeout` | `number` | `120000` | Timeout in milliseconds, clamped to 5000 to 600000 |
| `verifierCheckUrl` | `string \| null` | `'https://verify.signet.forgesworn.dev'` | Verification bot URL. Set to `null` to skip the check; unless `acceptUnconfirmed` is also `true`, `verified` is then `false` with `verifier-check-unavailable`. A URL that does not start with `https://` counts as a failed check |
| `acceptUnconfirmed` | `boolean` | `false` | Accept credentials from unconfirmed verifiers, and when the check is skipped or fails (see What `verified` is when the check is skipped or fails) |

**Result:**

| Field | Type | Description |
|-------|------|-------------|
| `verified` | `boolean` | `true` if credential valid, unexpired, age range met, AND verifier confirmed (or `acceptUnconfirmed` is true). With `verifierCheckUrl: null`, or when the check fails, `verifierConfirmed` is `null` and `verified` is `false` unless `acceptUnconfirmed` is true |
| `ageRange` | `string \| null` | Age range from the credential (e.g. `'18+'`) |
| `tier` | `number \| null` | Verification tier (1–4) |
| `entityType` | `string \| null` | `'natural_person'`, `'persona'`, etc. |
| `credentialId` | `string \| null` | ID of the credential event (`credential.id`) |
| `verifierPubkey` | `string \| null` | Professional keypair of the issuing verifier |
| `verifierConfirmed` | `boolean \| null` | Whether the verifier is confirmed against a public register. `null` if the check was skipped or unavailable. |
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
| `'verifier-check-unavailable'` | The verifier check was skipped (`verifierCheckUrl: null`) or failed (non-`https://` URL, bot unreachable, non-2xx or non-JSON answer). The credential is valid but the verifier status is unknown, so `verified` is `false` unless `acceptUnconfirmed` is true |

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
| `authEvent` | `SignetAuthEvent` | The signed kind-21236 event, verified in the browser by this package: `id`, `pubkey`, `kind`, `created_at`, `tags`, `content`, `sig` |
| `credential` | `unknown` (optional) | Credential included in the response (Signet Login flows), passed through as received, not checked by this package |
| `displayName` | `string` (optional) | Persona handle the user chose to share. Control and bidi characters are stripped and it is capped at 64 characters; still escape it when rendering |
| `bunkerUri` | `string` (optional) | A `bunker://` URI for upgrading to a live signer. Absent on auth-only flows. Only its `bunker://` prefix is checked |
| `createdAt` | `number` | Unix seconds at which the auth event was signed |

**Constants:** `AUTH_FRESHNESS_WINDOW_SEC` (`300`, seconds) and `DEFAULT_RELAY_URL` (`'wss://nos.lol'`).

### Verify the result on your server

`waitForAuthResponse` verifies the response in the browser, and a browser result is not evidence for your server: the user, or script running in the page, can send your server any `pubkey` or `SignetAuthResult` it likes. Re-verify on the server before you create a session. Send the whole `authEvent`, not only `pubkey`, and check all of the following there:

- `kind` is `21236` and the event's `id` and `sig` verify (`verifyEvent` from `nostr-tools/pure` recomputes the NIP-01 id and checks the BIP-340 signature).
- The `challenge` tag equals the challenge your server issued for this attempt. Accept each challenge once, then discard it.
- The `origin` tag equals your own origin exactly.
- `created_at` is within `AUTH_FRESHNESS_WINDOW_SEC` of the server clock.
- Take the user's identity from the verified `authEvent.pubkey`.

```ts
import { verifyEvent } from 'nostr-tools/pure';
import { AUTH_FRESHNESS_WINDOW_SEC, type SignetAuthEvent } from 'signet-verify';

// `pending` is what your server stored when it issued this sign-in.
function authEventIsValid(authEvent: SignetAuthEvent, pending: { challenge: string; origin: string }): boolean {
  const tag = (name: string) => authEvent.tags.find((t) => t[0] === name)?.[1];
  return (
    authEvent.kind === 21236 &&
    verifyEvent(authEvent) &&
    tag('challenge')?.toLowerCase() === pending.challenge.toLowerCase() &&
    tag('origin') === pending.origin &&
    Math.abs(Date.now() / 1000 - authEvent.created_at) <= AUTH_FRESHNESS_WINDOW_SEC
  );
}
```

Mint the challenge and `issuedAt` on the server and keep them against the pending sign-in. The cross-device example above mints them in the browser for brevity, and a challenge the client chose cannot be tied to an attempt your server started.

`credential` is `unknown` and is forwarded exactly as the response carried it. This package does not check its shape, signature or expiry, so validate it yourself or ignore it.

Alternatively, run `waitForAuthResponse` on the server (see Node, SSR and tests) and keep `sessionPrivKey` there. The result then never passes through the client.

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
- Proof verification runs in the browser. `verifyAge` makes one network request, to the verification bot, unless `verifierCheckUrl` is `null`; it opens no relay connection, and the proof reaches the modal over a same-origin `BroadcastChannel`, not the network. `waitForAuthResponse` connects only to the relay you give it
- The verifier check is a single GET request that sends only the verifier's public key and returns confirmed or not
