import { encryptBundle, decryptBundle } from "/crypto.js";
import { STRINGS, detectLang } from "/i18n.js";

const $ = (id) => document.getElementById(id);
let LANG = detectLang();
let CFG = { max_mb: 20, captcha: true, expiry_opts: ["1h","1d","7d","30d","never"], default_expiry: "7d" };
let FILES = [];           // pending files for create: {name, mime, bytes}
let challengeToken = null;

function t(k) { return (STRINGS[LANG] && STRINGS[LANG][k]) || STRINGS.en[k] || k; }

async function api(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

// ---- base64 of binary ----
function bytesToB64(bytes) {
  let s = "", chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(s);
}
function b64ToBytes(b64) {
  const bin = atob(b64), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function fmtBytes(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(0) + " kB" : (n/1048576).toFixed(1) + " MB"; }
function fmtDate(ts) {
  const d = new Date(ts * 1000), p = (x) => String(x).padStart(2, "0");
  return `${p(d.getDate())}.${p(d.getMonth()+1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ---- i18n application ----
function applyLang() {
  document.documentElement.lang = LANG;
  $("tagline").textContent = t("tagline");
  $("lblText").textContent = t("text_label");
  $("text").placeholder = t("text_ph");
  $("lblFiles").textContent = t("files_label");
  $("dropTxt").textContent = t("files_drop");
  $("lblPw").textContent = t("pw_label");
  $("pw").placeholder = t("pw_ph");
  $("pwHint").textContent = t("pw_hint");
  $("lblExpiry").textContent = t("expiry_label");
  $("lblBurn").textContent = t("burn_label");
  $("lblChallenge").textContent = t("challenge_label");
  $("createBtn").textContent = t("create_btn");
  $("resTitle").textContent = t("result_title");
  $("resHint").textContent = t("result_hint");
  $("copyBtn").textContent = t("copy");
  $("openLink").textContent = t("open_link");
  $("delBtn").textContent = t("delete_link");
  $("newBtn").textContent = t("new_one");
  $("delHint").textContent = t("delete_hint");
  $("unlockBtn").textContent = t("unlock");
  $("copyTextBtn").textContent = t("copy_text");
  $("footMsg").textContent = t("footer");
  // expiry options
  const sel = $("expiry"); sel.innerHTML = "";
  for (const k of CFG.expiry_opts) {
    const o = document.createElement("option");
    o.value = k; o.textContent = t("expiry_" + k);
    if (k === CFG.default_expiry) o.selected = true;
    sel.appendChild(o);
  }
  document.querySelectorAll(".langs button").forEach((b) =>
    b.classList.toggle("active", b.dataset.lang === LANG));
}

// ---- file handling ----
function renderFileList() {
  const ul = $("fileList"); ul.innerHTML = "";
  FILES.forEach((f, i) => {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = `${f.name} (${fmtBytes(f.bytes.length)})`;
    const x = document.createElement("button");
    x.textContent = "×"; x.title = "remove";
    x.onclick = () => { FILES.splice(i, 1); renderFileList(); };
    li.append(span, x); ul.appendChild(li);
  });
}
function addFiles(fileList) {
  for (const file of fileList) {
    const reader = new FileReader();
    reader.onload = () => {
      FILES.push({ name: file.name, mime: file.type || "application/octet-stream", bytes: new Uint8Array(reader.result) });
      renderFileList();
    };
    reader.readAsArrayBuffer(file);
  }
}

// ---- challenge ----
async function loadChallenge() {
  if (!CFG.captcha) { $("challengeWrap").classList.add("hidden"); return; }
  const r = await fetch("/api/challenge?lang=" + LANG);
  const d = await r.json();
  challengeToken = d.token;
  $("challengeQ").textContent = d.q;
  $("challengeWrap").classList.remove("hidden");
}

// ---- create flow ----
async function doCreate() {
  const err = $("createErr"); err.classList.add("hidden");
  const text = $("text").value;
  if (!text && FILES.length === 0) { err.textContent = t("empty"); err.classList.remove("hidden"); return; }
  const bundle = { text, files: FILES.map((f) => ({ name: f.name, mime: f.mime, b64: bytesToB64(f.bytes) })) };
  const pw = $("pw").value;
  const btn = $("createBtn"); btn.disabled = true; btn.textContent = t("creating");
  try {
    const { ctB64, fragmentKey } = await encryptBundle(bundle, pw);
    if (ctB64.length * 0.75 > CFG.max_mb * 1024 * 1024) { throw new Error(t("too_big")); }
    const body = { ct: ctB64, expiry: $("expiry").value, burn: $("burn").checked };
    if (CFG.captcha) { body.captcha_token = challengeToken; body.captcha_answer = $("challengeA").value; }
    const res = await api("/api/create", body);
    if (res.status !== 200) { throw new Error(res.json.error || t("err_generic")); }
    const url = `${res.json.url_base}#${fragmentKey}`;
    try { localStorage.setItem("del_" + res.json.id, res.json.del_token); } catch {}
    showResult(url, res.json.id, res.json.del_token);
  } catch (e) {
    err.textContent = e.message || t("err_generic"); err.classList.remove("hidden");
    if (CFG.captcha) loadChallenge();
  } finally {
    btn.disabled = false; btn.textContent = t("create_btn");
  }
}

function showResult(url, id, delToken) {
  $("createView").classList.add("hidden");
  $("resultView").classList.remove("hidden");
  $("shareUrl").value = url;
  $("openLink").href = url;
  $("delBtn").onclick = async () => {
    await api("/api/delete", { id, del_token: delToken });
    $("delBtn").textContent = t("copied"); $("delBtn").disabled = true;
  };
  $("newBtn").onclick = () => { location.href = "/"; };
}

// ---- read / decrypt flow ----
async function doRead(id) {
  $("createView").classList.add("hidden");
  $("readView").classList.remove("hidden");
  const fragKey = location.hash.replace(/^#/, "");
  const status = $("readStatus");
  if (!fragKey) { status.textContent = t("bad_link"); return; }
  status.textContent = t("decrypting");
  const res = await api("/api/get", { id });
  if (res.status !== 200) { status.textContent = t("not_found"); return; }
  const { ct, created, expires, burn } = res.json;

  const finish = (bundle) => {
    status.classList.add("hidden");
    $("pwPrompt").classList.add("hidden");
    $("content").classList.remove("hidden");
    if (bundle.text) {
      $("readText").textContent = bundle.text; $("readText").classList.remove("hidden");
      const cb = $("copyTextBtn"); cb.classList.remove("hidden");
      cb.onclick = () => navigator.clipboard.writeText(bundle.text).then(() => cb.textContent = t("copied"));
    }
    const ul = $("readFiles");
    (bundle.files || []).forEach((f) => {
      const bytes = b64ToBytes(f.b64);
      const blob = new Blob([bytes], { type: f.mime || "application/octet-stream" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = f.name || "file";
      a.textContent = `↓ ${f.name} (${fmtBytes(bytes.length)})`;
      const li = document.createElement("li"); li.appendChild(a); ul.appendChild(li);
    });
    let meta = `${t("created_at")}: ${fmtDate(created)} · ${t("expires_at")}: ${expires ? fmtDate(expires) : t("expires_never")}`;
    if (burn) meta = t("burned") + "\n" + meta;
    $("readMeta").textContent = meta;
  };

  // Try without a password first (zero-knowledge: the server never told us
  // whether a password was set). If GCM auth fails, prompt for one.
  try {
    finish(await decryptBundle(ct, fragKey, ""));
  } catch {
    status.classList.add("hidden");
    $("pwPrompt").classList.remove("hidden");
    $("pwPromptMsg").textContent = t("enter_pw");
    const attempt = async () => {
      $("pwErr").classList.add("hidden");
      try { finish(await decryptBundle(ct, fragKey, $("readPw").value)); }
      catch { $("pwErr").textContent = t("wrong_pw"); $("pwErr").classList.remove("hidden"); }
    };
    $("unlockBtn").onclick = attempt;
    $("readPw").onkeydown = (e) => { if (e.key === "Enter") attempt(); };
    $("readPw").focus();
  }
}

// ---- boot ----
async function boot() {
  try { CFG = await (await fetch("/api/config")).json(); } catch {}
  const m = location.pathname.match(/^\/c\/([A-Za-z0-9_-]+)$/);
  const isRead = !!m;
  applyLang();
  document.querySelectorAll(".langs button").forEach((b) =>
    b.onclick = () => { LANG = b.dataset.lang; localStorage.setItem("clip_lang", LANG); applyLang(); if (!isRead) loadChallenge(); });

  if (isRead) { doRead(m[1]); return; }

  $("createView").classList.remove("hidden");
  // drag & drop
  const drop = $("drop"), fi = $("fileInput");
  drop.onclick = () => fi.click();
  fi.onchange = () => { addFiles(fi.files); fi.value = ""; };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); addFiles(e.dataTransfer.files); };
  $("createBtn").onclick = doCreate;
  loadChallenge();
}
boot();
