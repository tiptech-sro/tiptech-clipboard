// Zero-knowledge crypto for tiptech-clipboard.
//
// The plaintext never leaves the browser unencrypted. We:
//   1. generate a random 256-bit key,
//   2. derive an AES-GCM key from (random key [+ optional password]) via PBKDF2,
//   3. AES-256-GCM encrypt the bundle (text + files) into one blob.
//
// The random key is placed in the URL fragment (#...) by the app, which browsers
// never transmit to the server. The server stores only the ciphertext and cannot
// decrypt it - there is no master key on the server side.
//
// This module is plain ES modules and runs unchanged in a modern browser and in
// Node.js >= 20 (which exposes the same globalThis.crypto.subtle), so the exact
// same code path is covered by the test suite.

const subtle = globalThis.crypto.subtle;
const PBKDF2_ITER = 310000;
const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MAGIC = 0x54430201; // "TC" + version 2.1, sanity marker in the header

const enc = new TextEncoder();
const dec = new TextDecoder();

function rand(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ---- base64url helpers (for the URL-fragment key) ----
export function b64uEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- standard base64 (for the ciphertext blob sent to the server) ----
function b64Encode(bytes) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}
function b64Decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(keyBytes, password, salt) {
  // Key material = random key bytes concatenated with the optional password.
  // Without the URL-fragment key you cannot derive the AES key even if you know
  // the password; with a password set you additionally need it.
  const pwBytes = password ? enc.encode(password) : new Uint8Array(0);
  const material = new Uint8Array(keyBytes.length + pwBytes.length);
  material.set(keyBytes, 0);
  material.set(pwBytes, keyBytes.length);
  const base = await subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Bundle layout (before encryption): JSON { text, files:[{name,mime,b64}] }
// Blob layout (what goes to the server): [4B magic][16B salt][12B iv][ciphertext]
export async function encryptBundle(bundle, password) {
  const keyBytes = rand(KEY_BYTES);
  const salt = rand(SALT_BYTES);
  const iv = rand(IV_BYTES);
  const key = await deriveKey(keyBytes, password || "", salt);
  const plain = enc.encode(JSON.stringify(bundle));
  const ctBuf = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, plain));

  const header = new Uint8Array(4 + SALT_BYTES + IV_BYTES);
  new DataView(header.buffer).setUint32(0, MAGIC, false);
  header.set(salt, 4);
  header.set(iv, 4 + SALT_BYTES);

  const blob = new Uint8Array(header.length + ctBuf.length);
  blob.set(header, 0);
  blob.set(ctBuf, header.length);
  return { ctB64: b64Encode(blob), fragmentKey: b64uEncode(keyBytes) };
}

export async function decryptBundle(ctB64, fragmentKey, password) {
  const blob = b64Decode(ctB64);
  if (blob.length < 4 + SALT_BYTES + IV_BYTES) throw new Error("corrupt");
  if (new DataView(blob.buffer, blob.byteOffset, 4).getUint32(0, false) !== MAGIC)
    throw new Error("bad-format");
  const salt = blob.subarray(4, 4 + SALT_BYTES);
  const iv = blob.subarray(4 + SALT_BYTES, 4 + SALT_BYTES + IV_BYTES);
  const ct = blob.subarray(4 + SALT_BYTES + IV_BYTES);
  const keyBytes = b64uDecode(fragmentKey);
  const key = await deriveKey(keyBytes, password || "", salt);
  // Throws OperationError on wrong key/password (GCM auth tag mismatch).
  const plain = await subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(dec.decode(plain));
}
