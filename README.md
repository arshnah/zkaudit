# zkaudit

A tool that checks whether a "zero-knowledge" or end-to-end-encrypted claim actually holds up, by scanning a real browser network capture for plaintext leaks.

## Why this exists

Most "zero-knowledge" claims aren't independently checkable. You either trust the marketing copy or read the source yourself. This gives you a third option: perform the real action in your browser (send a message, upload a file), export the network capture, and have this tool check whether the plaintext, or the encryption key, ever actually left your browser.

## How it works

1. Do the thing you want to audit in your browser (type a distinctive message, upload a file with known contents) with DevTools open.
2. Export the capture: DevTools → Network tab → right-click → "Save all as HAR with content".
3. Run zkaudit against it with the exact plaintext you used.

```
go run ./cmd/zkaudit -har capture.har -secrets "the exact message I typed,my-encryption-passphrase"
```

zkaudit scans every request URL, request headers, request body, response headers, and response body (including base64-decoded response bodies) in the capture for the plaintext, and for URL-encoded, base64-encoded, and case-folded variants of it. Any match is a leak: it means the server saw something it shouldn't have if the claim is real zero-knowledge.

Use a real secret, not a short one. A 2-character string will match constantly by coincidence, inside ordinary words, inside binary noise. zkaudit warns if a secret is under 8 characters, but the honest fix is to use something distinctive.

It also flags request bodies with a strong ciphertext signature: either high base64-character density, or high byte-level Shannon entropy. Not proof of correct encryption by itself, but useful context alongside a clean scan.

## Multiple flows

Most real apps have more than one flow worth auditing (upload, share, view/decrypt). Capture each separately, then pass them all at once:

```
go run ./cmd/zkaudit -har upload.har,view.har,share.har -secrets "..." -target "my app" -report audit.md -badge audit.svg
```

`-report` writes a markdown audit report, `-badge` writes a pass/fail SVG badge.

## Sharing a capture safely

HAR files can contain session cookies and auth tokens. Before sharing one (with me, with anyone), strip that out:

```
go run ./cmd/zkaudit -har capture.har -redact-out sanitized.har
```

This replaces Cookie, Set-Cookie, Authorization, and similar header values, plus any HAR-level cookie entries, with `[REDACTED]`. It doesn't touch anything else, the actual request/response bodies being audited are left intact.

## What a PASS actually means

A PASS means: across every network request captured during that session, the exact plaintext you provided never appeared anywhere, not the URL, not the headers, not either body. It does not mean the encryption is cryptographically sound, that's a separate question. It means the server-side plaintext exposure a "zero-knowledge" claim promises to prevent didn't happen during that specific captured session.

## What this is NOT

Not a cryptographic audit. Not a proof that the client-side crypto implementation is correct, only that plaintext didn't leak over the wire during the captured session. Not exhaustive, only covers the interactions you actually captured, if a site has multiple flows (upload, share, view) each should be captured and audited separately. Not automated against arbitrary third-party sites, you have to actually perform and capture the action yourself, which is also what makes it honest: it's checking real traffic, not a scripted best-case demo.

## Status

Core scanning engine, multi-flow support, redaction, and report/badge generation are implemented and tested, both against synthetic fixtures and real captured traffic.

Already ran a real audit against CipherDrop's upload flow: PASS, using a distinctive test secret, on the actual production POST body. The redaction feature was also checked against that same capture, it genuinely has no cookies to strip (that endpoint doesn't use session auth), which is itself a useful fact to have confirmed rather than assumed.

Two real bugs were found and fixed by actually running this against live traffic, not just synthetic tests: a duplicate-finding bug when a secret's case-folded variant equals the original, and a false-positive storm from a 2-character test secret matching common substrings inside ordinary words. A third real fix came from the ciphertext heuristic itself: entropy calculated over Unicode runes silently corrupts on genuine binary ciphertext, since invalid UTF-8 byte sequences collapse into repeated replacement characters and understate entropy, so the heuristic never fired on CipherDrop's actual (non-base64, raw binary) payload until it was switched to byte-level entropy.
