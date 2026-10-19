// JS → Python istiqaməti: brauzer kodu paylanma qurur, Python onu açmalıdır.
// tests/test_crossimpl.py bu skripti işə salır. (Şəxsi açarlar yalnız TEST üçün çıxarılır.)
import * as C from "../../web/js/crypto.js";

const vaultId = "v_" + C.b64u(C.randomBytes(16));
const dek = C.randomBytes(32);
const R = C.randomBytes(32);
const trustees = [];
for (let i = 0; i < 3; i++) {
  const kp = await C.generateKeypair();
  trustees.push({ id: `u_trustee${i}aaaaaaaaaaaaaaa`, public_key: C.b64u(await C.exportPublicRaw(kp.publicKey)),
    pkcs8: C.b64u(await C.exportPrivatePkcs8(kp.privateKey)) });
}
const dist = await C.buildDistribution({ vaultId, dek, releaseKey: R, threshold: 2, trustees });
const content = { items: [{ title: "JS-də şifrələndi", secret: "Ə-ğ-ü-ş-ç-ı-ö 🔐" }] };
const box = await C.encryptVault(dek, vaultId, 7, content);
const mk = await C.masterKey("JS parolu — 2026", new Uint8Array(16).fill(5));
const keys = await C.deriveUserKeys(mk);
console.log(JSON.stringify({
  vaultId, dek: C.b64u(dek), R: C.b64u(R), trustees, dist, box, content,
  kdf: { master: C.b64u(mk), auth: C.b64u(keys.authKey), enc: C.b64u(keys.encKey) },
  fingerprint: await C.fingerprint(C.b64uD(trustees[0].public_key)),
}));
