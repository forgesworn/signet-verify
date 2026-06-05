# Changelog

## 0.5.0 (2026-06-05)

### Features

- surface bunkerUri from the auth response (cross-device signer upgrade)



## 0.3.1 (2026-05-03)

### Bug Fixes

- bump to publish 0.3.0 displayName feature to npm (#11) (release)



## 0.3.0 (2026-05-03)

### Features

- surface displayName from AuthResponse, sanitised (#9) (auth)



## 0.2.2 (2026-05-03)

### Features

- `SignetAuthResult.displayName?: string` — surfaces the user's persona handle when they opted to share it on the approval screen. Mirrors the `display_name` URL param delivered by the redirect-back flow. Sanitised on receipt: control + bidi characters stripped, capped at 64 chars, empty values dropped.



## 0.2.1 (2026-04-18)

### Bug Fixes

- use published signet-protocol@^1.6.0, not file:../signet (deps)



## 0.2.0 (2026-04-18)

### Features

- reshape signet-verify as a proper ESM npm package
- waitForAuthResponse SDK helper for cross-device login
- initial release of signet-verify — drop-in age verification SDK

### Bug Fixes

- bump esbuild to ^0.25.12 (GHSA-67mh-4wv8-2f99) (deps)


