// Əmanət brauzer kriptoqrafiyası — yalnız WebCrypto (xarici kitabxana yoxdur).
// `emanet/crypto/primitives.py` ilə eyni format: tests/js/crossimpl.test.mjs.
// Bu fayldakı açarlar (master açar, enc açarı, şəxsi açar, DEK, S) brauzerdən heç vaxt çıxmır.

import * as shamir from "./shamir.js";

export const PROTOCOL = "emanet/v1";
export const PBKDF2_ITERATIONS = 600000;
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export class CryptoError extends Error {}

// ------------------------------------------------------------ kodlaşdırma
export function b64u(bytes) {
  let s = "";
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uD(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new CryptoError("yanlış base64url");
  const s = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);
export function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));   // WebCrypto limiti 64 KiB
  return out;
}
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export function hex(bytes) { return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""); }

// ------------------------------------------------------------ KDF
export async function hkdf(ikm, info, salt = new Uint8Array(0), length = 32) {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: utf8(info) }, k, length * 8));
}

export async function masterKey(password, kdfSalt, iterations = PBKDF2_ITERATIONS) {
  const pw = utf8(password.normalize("NFKC"));
  const k = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const salt = concat(utf8(PROTOCOL + "|"), kdfSalt);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, k, 256));
}

export async function deriveUserKeys(mk) {
  return { authKey: await hkdf(mk, `${PROTOCOL}/auth`), encKey: await hkdf(mk, `${PROTOCOL}/enc`) };
}

// ------------------------------------------------------------ AES-GCM
async function aesKey(raw) { return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]); }

export async function seal(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, await aesKey(key), plaintext);
  return { v: 1, iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

export async function openSealed(key, box, aad) {
  if (!box || box.v !== 1) throw new CryptoError("naməlum versiya");
  try {
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: b64uD(box.iv), additionalData: utf8(aad) },
      await aesKey(key), b64uD(box.ct));
    return new Uint8Array(pt);
  } catch (e) {
    throw new CryptoError("şifrəaçma uğursuz oldu");
  }
}

// ------------------------------------------------------------ AAD / kontekstlər
export const aadVault = (vaultId, version) => `${PROTOCOL}/vault|${vaultId}|${version}`;
export const aadDek = (vaultId, purpose) => {
  if (!["owner", "release", "recovery"].includes(purpose)) throw new RangeError("purpose");
  return `${PROTOCOL}/dek/${purpose}|${vaultId}`;
};
export const aadPrivkey = (userId, purpose = "enc") => `${PROTOCOL}/privkey/${purpose}|${userId}`;
export const ctxShare = (vaultId, trusteeId, x) => `${PROTOCOL}/share|${vaultId}|${trusteeId}|${x}`;
export const ctxHandoff = (vaultId, fromId, toId, x) => `${PROTOCOL}/handoff|${vaultId}|${fromId}|${toId}|${x}`;

// ------------------------------------------------------------ iki açarlı kilid
export async function releaseKek(S, R, vaultId) {
  if (S.length !== 32 || R.length !== 32) throw new RangeError("S və R 32 bayt olmalıdır");
  return hkdf(concat(S, R), `${PROTOCOL}/release-kek`, utf8(vaultId));
}

export async function sha256(bytes) { return new Uint8Array(await subtle.digest("SHA-256", bytes)); }

export async function shareCommitment(vaultId, shareBytes) {
  return hex(await sha256(concat(utf8(`${PROTOCOL}/share-commit|${vaultId}|`), shareBytes)));
}

// ------------------------------------------------------------ ölçünü gizlətmə
export function pad(data) {
  const raw = new Uint8Array(4 + data.length);
  new DataView(raw.buffer).setUint32(0, data.length);
  raw.set(data, 4);
  const block = raw.length <= 65536 ? 4096 : 65536;
  const total = Math.ceil(raw.length / block) * block;
  const out = new Uint8Array(total);
  out.set(raw);
  return out;
}
export function unpad(data) {
  if (data.length < 4) throw new CryptoError("yanlış doldurma");
  const n = new DataView(data.buffer, data.byteOffset).getUint32(0);
  if (n > data.length - 4) throw new CryptoError("yanlış doldurma");
  for (let i = 4 + n; i < data.length; i++) if (data[i] !== 0) throw new CryptoError("yanlış doldurma");
  return data.slice(4, 4 + n);
}

// ------------------------------------------------------------ ECIES P-256
export async function generateKeypair() {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}
export async function exportPublicRaw(pub) { return new Uint8Array(await subtle.exportKey("raw", pub)); }
export async function importPublicRaw(raw) {
  if (raw.length !== 65 || raw[0] !== 4) throw new CryptoError("yanlış açıq açar formatı");
  try {
    return await subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
  } catch (e) { throw new CryptoError("açıq açar əyri üzərində deyil"); }
}
export async function exportPrivatePkcs8(priv) { return new Uint8Array(await subtle.exportKey("pkcs8", priv)); }
export async function importPrivatePkcs8(der) {
  return subtle.importKey("pkcs8", der, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

export async function fingerprint(rawPub) {
  const h = hex(await sha256(concat(utf8(`${PROTOCOL}/fp|`), rawPub))).slice(0, 32).toUpperCase();
  return h.match(/.{4}/g).join(" ");
}

export async function eciesEncrypt(recipientRaw, plaintext, context) {
  const recipient = await importPublicRaw(recipientRaw);
  const eph = await generateKeypair();
  const epk = await exportPublicRaw(eph.publicKey);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: recipient }, eph.privateKey, 256));
  const key = await hkdf(shared, `${PROTOCOL}/ecies|${context}`, epk);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(context) }, await aesKey(key), plaintext);
  return { v: 1, epk: b64u(epk), iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

export async function eciesDecrypt(priv, box, context) {
  if (!box || box.v !== 1) throw new CryptoError("naməlum versiya");
  try {
    const epk = b64uD(box.epk);
    const pub = await importPublicRaw(epk);
    const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
    const key = await hkdf(shared, `${PROTOCOL}/ecies|${context}`, epk);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: b64uD(box.iv), additionalData: utf8(context) },
      await aesKey(key), b64uD(box.ct));
    return new Uint8Array(pt);
  } catch (e) {
    throw new CryptoError("ECIES şifrəaçma uğursuz oldu");
  }
}

// ------------------------------------------------------------ bərpa kodu
export const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export function newRecoveryCode() {
  const chars = [...randomBytes(25)].map((b) => RECOVERY_ALPHABET[b % 32]).join("");
  return chars.match(/.{5}/g).join("-");
}
export async function recoveryKeys(code) {
  const norm = code.replace(/[-\s]/g, "").toUpperCase();
  if (norm.length !== 25 || [...norm].some((c) => !RECOVERY_ALPHABET.includes(c))) throw new CryptoError("yanlış bərpa kodu");
  const ikm = utf8(norm);
  return { authKey: await hkdf(ikm, `${PROTOCOL}/recovery-auth`), encKey: await hkdf(ikm, `${PROTOCOL}/recovery-enc`) };
}

// ------------------------------------------------------------ yüksək səviyyəli əməliyyatlar
/** Seyfin məzmununu (JS obyekt) DEK ilə şifrələ. */
export async function encryptVault(dek, vaultId, version, contentObj) {
  return seal(dek, pad(utf8(JSON.stringify(contentObj))), aadVault(vaultId, version));
}
export async function decryptVault(dek, vaultId, version, box) {
  return JSON.parse(fromUtf8(unpad(await openSealed(dek, box, aadVault(vaultId, version)))));
}

/**
 * Etibarlı şəxslər üçün paylanma paketi hazırla (hamısı brauzerdə):
 *  S təsadüfi → Shamir(t, n) → hər hissə müvafiq şəxsin açıq açarına ECIES ilə;
 *  DEK, KEK = HKDF(S‖R) ilə sarılır. Server yalnız şifrəli hissələri və sarınmış DEK-i görür.
 */
export async function buildDistribution({ vaultId, dek, releaseKey, threshold, trustees, rng }) {
  const S = randomBytes(32);
  const shares = shamir.split(S, trustees.length, threshold, rng);
  const kek = await releaseKek(S, releaseKey, vaultId);
  const wrappedDekRelease = await seal(kek, dek, aadDek(vaultId, "release"));
  const out = [];
  for (let i = 0; i < trustees.length; i++) {
    const t = trustees[i];
    const sb = shamir.shareToBytes(shares[i]);
    out.push({
      trustee_id: t.id,
      x: shares[i].x,
      commitment: await shareCommitment(vaultId, sb),
      box: await eciesEncrypt(b64uD(t.public_key), sb, ctxShare(vaultId, t.id, shares[i].x)),
    });
  }
  S.fill(0);
  return { wrappedDekRelease, shares: out };
}

/** Bərpa: t hissə + R → DEK. Öhdəlik (commitment) uyğunsuz hissəni ad ilə göstərir. */
export async function recoverDek({ vaultId, releaseKey, wrappedDekRelease, shares, commitments }) {
  const bad = [];
  const good = [];
  for (const s of shares) {
    const c = await shareCommitment(vaultId, s.bytes);
    if (commitments[s.x] !== c) bad.push(s.x); else good.push(shamir.shareFromBytes(s.bytes));
  }
  if (bad.length) throw new CryptoError(`saxta və ya korlanmış hissə: #${bad.join(", #")}`);
  const S = shamir.combine(good);
  const kek = await releaseKek(S, releaseKey, vaultId);
  return openSealed(kek, wrappedDekRelease, aadDek(vaultId, "release"));
}

export { shamir };
