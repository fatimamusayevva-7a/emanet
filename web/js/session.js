// Brauzer sessiyası: açarlar YALNIZ yaddaşda (JS dəyişənlərində) saxlanılır.
// localStorage/sessionStorage/IndexedDB-yə heç nə yazılmır — səhifə yenilənəndə
// seyf "kilidlənir" və parol yenidən soruşulur.
import * as C from "./crypto.js";
import * as A from "./api.js";

export const S = { user: null, encKey: null, priv: null, vaultId: null, demo: false, dek: null };

export function clear() {
  if (S.encKey) S.encKey.fill(0);
  if (S.dek) S.dek.fill(0);
  Object.assign(S, { user: null, encKey: null, priv: null, vaultId: null, dek: null });
}

async function unwrapPriv(encKey, userId, box, purpose = "enc") {
  const der = await C.openSealed(encKey, box, C.aadPrivkey(userId, purpose));
  return C.importPrivatePkcs8(der);
}

export async function deriveForEmail(email, password) {
  const pre = await A.post("/api/auth/prelogin", { email });
  const mk = await C.masterKey(password, C.b64uD(pre.kdf_salt), pre.kdf_iterations);
  const keys = await C.deriveUserKeys(mk);
  mk.fill(0);
  return keys;
}

export async function register({ email, name, password }) {
  const userId = "u_" + C.b64u(C.randomBytes(16));
  const salt = C.randomBytes(16);
  const mk = await C.masterKey(password, salt);
  const { authKey, encKey } = await C.deriveUserKeys(mk);
  const kp = await C.generateKeypair();
  const pub = await C.exportPublicRaw(kp.publicKey);
  const der = await C.exportPrivatePkcs8(kp.privateKey);
  const recoveryCode = C.newRecoveryCode();
  const rk = await C.recoveryKeys(recoveryCode);
  await A.post("/api/auth/register", {
    user_id: userId, email, display_name: name, kdf_salt: C.b64u(salt), auth_key: C.b64u(authKey),
    public_key: C.b64u(pub), wrapped_privkey: await C.seal(encKey, der, C.aadPrivkey(userId)),
    recovery_auth: C.b64u(rk.authKey), wrapped_privkey_recovery: await C.seal(rk.encKey, der, C.aadPrivkey(userId, "recovery")),
  });
  der.fill(0);
  return { recoveryCode, rk };
}

export async function login({ email, password, totp }) {
  const { authKey, encKey } = await deriveForEmail(email, password);
  const body = { email, auth_key: C.b64u(authKey) };
  if (totp) body.totp = totp;
  const r = await A.post("/api/auth/login", body);
  A.setCsrf(r.csrf);
  S.user = r.user;
  S.encKey = encKey;
  S.priv = await unwrapPriv(encKey, r.user.id, r.user.wrapped_privkey);
  const me = await A.get("/api/me");
  S.vaultId = me.vault_id; S.demo = me.demo_mode;
  return r;
}

/** Sessiya cookie-si qalıb, amma səhifə yenilənib → yalnız parol ilə "kilidi aç". */
export async function unlock(password) {
  const { encKey } = await deriveForEmail(S.user.email, password);
  S.priv = await unwrapPriv(encKey, S.user.id, S.user.wrapped_privkey);   // yanlış parol → CryptoError
  S.encKey = encKey;
}

export async function resume() {
  try {
    const probe = await A.get("/api/session");
    if (!probe.authenticated) return false;
    const me = await A.get("/api/me");
    A.setCsrf(me.csrf);
    S.user = me.user; S.vaultId = me.vault_id; S.demo = me.demo_mode;
    return true;
  } catch { return false; }
}

export async function logout() {
  try { await A.post("/api/auth/logout"); } catch { /* sessiya artıq bitib */ }
  clear(); A.setCsrf(null);
}

/** Qeydiyyatdan dərhal sonra seyf yaradılır — bərpa kodu hələ yaddaşdadır. */
export async function createVault(rk) {
  const vaultId = "v_" + C.b64u(C.randomBytes(16));
  const dek = C.randomBytes(32);
  const r = await A.post("/api/vault", {
    vault_id: vaultId,
    wrapped_dek_owner: await C.seal(S.encKey, dek, C.aadDek(vaultId, "owner")),
    wrapped_dek_recovery: await C.seal(rk.encKey, dek, C.aadDek(vaultId, "recovery")),
  });
  S.vaultId = r.vault_id; S.dek = dek;
  await saveContent(1, { items: [], letter: "", created: Date.now() });
  return r;
}

export async function loadVault() {
  const v = await A.get("/api/vault");
  if (!S.dek) S.dek = await C.openSealed(S.encKey, v.wrapped_dek_owner, C.aadDek(S.vaultId, "owner"));
  return v;
}

export async function loadContent() {
  const r = await A.get("/api/vault/content");
  if (!r.box) return { version: 0, content: { items: [], letter: "" } };
  return { version: r.version, content: await C.decryptVault(S.dek, S.vaultId, r.version, r.box) };
}

export async function saveContent(version, content) {
  const box = await C.encryptVault(S.dek, S.vaultId, version, content);
  return A.put("/api/vault/content", { version, box });
}

export async function distribute(threshold, trustees) {
  const { release_key } = await A.get("/api/vault/release-key");
  const R = C.b64uD(release_key);
  const d = await C.buildDistribution({ vaultId: S.vaultId, dek: S.dek, releaseKey: R, threshold,
    trustees: trustees.map((t) => ({ id: t.user_id, public_key: t.public_key, tid: t.id })) });
  R.fill(0);
  const byUser = Object.fromEntries(trustees.map((t) => [t.user_id, t.id]));
  return A.post("/api/vault/distribution", {
    threshold, wrapped_dek_release: d.wrappedDekRelease,
    shares: d.shares.map((s) => ({ trustee_id: byUser[s.trustee_id], x: s.x, commitment: s.commitment, box: s.box })),
  });
}

// ------------------------------------------------------------ etibarlı şəxs tərəfi
export async function fetchMaterial(vaultId) { return A.get(`/api/trustee/vaults/${vaultId}/release`); }

async function myShareBytes(m) {
  return C.eciesDecrypt(S.priv, m.my_share.box, C.ctxShare(m.vault_id, S.user.id, m.my_share.x));
}

/** Öz hissəmi digər etibarlı şəxslərin açıq açarlarına şifrələyib ötürürəm. */
export async function handOff(m) {
  const sb = await myShareBytes(m);
  const items = [];
  for (const o of m.others) {
    items.push({ to_user: o.user_id, x: m.my_share.x,
      box: await C.eciesEncrypt(C.b64uD(o.public_key), sb, C.ctxHandoff(m.vault_id, S.user.id, o.user_id, m.my_share.x)) });
  }
  sb.fill(0);
  return A.post(`/api/trustee/vaults/${m.vault_id}/handoffs`, { items });
}

/** Mövcud hissələri topla; kifayətdirsə seyfi aç. */
export async function tryOpen(m) {
  const shares = [{ x: m.my_share.x, bytes: await myShareBytes(m) }];
  for (const hnd of m.handoffs) {
    shares.push({ x: hnd.x, bytes: await C.eciesDecrypt(S.priv, hnd.box, C.ctxHandoff(m.vault_id, hnd.from_user, S.user.id, hnd.x)) });
  }
  if (shares.length < m.threshold) return { opened: false, have: shares.length, need: m.threshold };
  const dek = await C.recoverDek({ vaultId: m.vault_id, releaseKey: C.b64uD(m.release_key),
    wrappedDekRelease: m.wrapped_dek_release, shares, commitments: m.commitments });
  const content = await C.decryptVault(dek, m.vault_id, m.content.version, m.content.box);
  dek.fill(0);
  return { opened: true, have: shares.length, need: m.threshold, content };
}

// ------------------------------------------------------------ bərpa kodu ilə bərpa
export async function recover({ email, code, newPassword }) {
  const rk = await C.recoveryKeys(code);
  const r = await A.post("/api/auth/recover/begin", { email, recovery_auth: C.b64u(rk.authKey) });
  const der = await C.openSealed(rk.encKey, r.wrapped_privkey_recovery, C.aadPrivkey(r.user_id, "recovery"));
  const salt = C.randomBytes(16);
  const { authKey, encKey } = await C.deriveUserKeys(await C.masterKey(newPassword, salt));
  const newCode = C.newRecoveryCode();
  const nrk = await C.recoveryKeys(newCode);
  const body = {
    email, recovery_auth: C.b64u(rk.authKey), kdf_salt: C.b64u(salt), auth_key: C.b64u(authKey),
    wrapped_privkey: await C.seal(encKey, der, C.aadPrivkey(r.user_id)),
    new_recovery_auth: C.b64u(nrk.authKey),
    new_wrapped_privkey_recovery: await C.seal(nrk.encKey, der, C.aadPrivkey(r.user_id, "recovery")),
  };
  if (r.vault_id && r.wrapped_dek_recovery) {
    const dek = await C.openSealed(rk.encKey, r.wrapped_dek_recovery, C.aadDek(r.vault_id, "recovery"));
    body.wrapped_dek_owner = await C.seal(encKey, dek, C.aadDek(r.vault_id, "owner"));
    body.wrapped_dek_recovery = await C.seal(nrk.encKey, dek, C.aadDek(r.vault_id, "recovery"));
    dek.fill(0);
  }
  der.fill(0);
  await A.post("/api/auth/recover/complete", body);
  return { newCode };
}
