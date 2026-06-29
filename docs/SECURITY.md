# Security model

## What "zero-knowledge" means here

All encryption and decryption happen in the browser using the Web Crypto API.
The server only ever receives an opaque ciphertext blob. There is no master key
on the server and no decryption path in the server code. The operator (and
anyone who compromises the server or its database) cannot read your content.

## How a clipboard is protected

1. The browser generates a random 256-bit key.
2. It derives an AES-256-GCM key from that random key (optionally concatenated
   with a user password) via PBKDF2-HMAC-SHA256, 310,000 iterations, with a
   random 16-byte salt.
3. The text and any files are bundled into one JSON document and encrypted with
   AES-256-GCM (random 12-byte IV).
4. Only the ciphertext, salt and IV are uploaded. The random key is placed in
   the URL fragment (`https://host/c/<id>#<key>`).

Browsers never send the fragment (`#...`) to the server, so the key that can
decrypt the content is never transmitted. The share link itself is the secret.

## The optional password

A password is mixed into the key derivation. When set, decryption requires
**both** the URL-fragment key and the password. Use it as a second factor in
case the link leaks (chat history, server logs of an intermediary, etc.).

## What the server stores

| Field      | Stored | Readable by operator |
|------------|--------|----------------------|
| Ciphertext | yes    | no (no key)          |
| Salt, IV   | yes    | yes (useless alone)  |
| Created / expiry / burn flag | yes | yes |
| Creator IP | yes (for rate limiting) | yes |
| Plaintext, filenames, file types, password | no | no |

Filenames and MIME types live **inside** the encrypted bundle, so the server
does not learn them either.

## Burn after reading

If enabled, the server deletes the record the first time it is retrieved.
Retrieval is a `POST`, so link-preview bots and email scanners (which issue
`GET` requests) do not consume it.

## Trade-off: no server-side content scanning

Because the server never sees plaintext, it cannot scan, sanitize or moderate
content (no image re-encoding, no PDF sanitization, no antivirus). This is the
inherent cost of zero-knowledge. Recipients decrypt locally and should treat
downloaded files as they would any file received from another person.

If you need server-side moderation, zero-knowledge is the wrong model for you.

## Reporting

Found a problem? Open a GitHub issue, or for sensitive reports email the address
listed in the repository profile.
