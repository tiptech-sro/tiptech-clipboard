// End-to-end test: runs the real browser crypto (static/crypto.js) against a
// live server.py. Proves the zero-knowledge contract: server stores only an
// opaque blob it cannot read, round-trips decrypt correctly, password and
// burn-after-read behave, and tampering fails closed.
import { encryptBundle, decryptBundle } from "../static/crypto.js";
import { readFileSync } from "node:fs";

const BASE = process.env.BASE || "http://127.0.0.1:8471";
let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log("  ok  -", name); }
  else { fail++; console.log("  FAIL-", name); }
}
async function api(path, body) {
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

async function main() {
  // ---- 1. round trip, no password ----
  const bundle = { text: "tajný text · diakritika ľščťžýáíé", files: [
    { name: "note.txt", mime: "text/plain", b64: Buffer.from("hello file").toString("base64") },
  ] };
  const { ctB64, fragmentKey } = await encryptBundle(bundle, "");
  const cr = await api("/api/create", { ct: ctB64, expiry: "7d" });
  ok("create returns id", cr.status === 200 && !!cr.json.id);
  ok("create returns del_token", !!cr.json.del_token);

  const got = await api("/api/get", { id: cr.json.id });
  ok("get returns ciphertext", got.status === 200 && got.json.ct === ctB64);
  const round = await decryptBundle(got.json.ct, fragmentKey, "");
  ok("decrypted text matches", round.text === bundle.text);
  ok("decrypted file matches", round.files[0].b64 === bundle.files[0].b64);

  // ---- 2. server truly cannot read it ----
  ok("ciphertext does not contain plaintext", !ctB64.includes(Buffer.from(bundle.text).toString("base64")) &&
     !Buffer.from(ctB64, "base64").toString("latin1").includes("tajný"));

  // ---- 3. wrong fragment key fails closed ----
  let threw = false;
  try { await decryptBundle(got.json.ct, fragmentKey.slice(0, -2) + "AA", ""); } catch { threw = true; }
  ok("wrong key throws", threw);

  // ---- 4. password path ----
  const e2 = await encryptBundle({ text: "with password" }, "hunter2");
  const c2 = await api("/api/create", { ct: e2.ctB64 });
  const g2 = await api("/api/get", { id: c2.json.id });
  let wrongPw = false;
  try { await decryptBundle(g2.json.ct, e2.fragmentKey, "wrong"); } catch { wrongPw = true; }
  ok("wrong password throws", wrongPw);
  const okPw = await decryptBundle(g2.json.ct, e2.fragmentKey, "hunter2");
  ok("right password decrypts", okPw.text === "with password");
  // even the correct password without the fragment key cannot decrypt
  let noKey = false;
  try { await decryptBundle(g2.json.ct, e2.fragmentKey.slice(0, -2) + "AA", "hunter2"); } catch { noKey = true; }
  ok("password alone (wrong key) fails", noKey);

  // ---- 5. burn after reading ----
  const e3 = await encryptBundle({ text: "burn me" }, "");
  const c3 = await api("/api/create", { ct: e3.ctB64, burn: true });
  const g3a = await api("/api/get", { id: c3.json.id });
  ok("burn: first read ok", g3a.status === 200);
  const g3b = await api("/api/get", { id: c3.json.id });
  ok("burn: second read gone (404)", g3b.status === 404);

  // ---- 6. delete via del_token ----
  const e4 = await encryptBundle({ text: "delete me" }, "");
  const c4 = await api("/api/create", { ct: e4.ctB64 });
  const dBad = await api("/api/delete", { id: c4.json.id, del_token: "nope" });
  ok("delete with bad token rejected (403)", dBad.status === 403);
  const dOk = await api("/api/delete", { id: c4.json.id, del_token: c4.json.del_token });
  ok("delete with good token ok", dOk.status === 200);
  const g4 = await api("/api/get", { id: c4.json.id });
  ok("deleted entry is gone (404)", g4.status === 404);

  // ---- 7. oversized rejected ----
  const big = "A".repeat(40 * 1024 * 1024);
  const cBig = await api("/api/create", { ct: Buffer.from(big).toString("base64") });
  ok("oversized payload rejected (400)", cBig.status === 400);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
