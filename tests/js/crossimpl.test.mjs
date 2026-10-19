// Python ↔ JS uyğunluğu: Python-un yaratdığı vektorları JS eyni şəkildə hesablamalı/açmalıdır.
// İşə salma: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import * as C from "../../web/js/crypto.js";
import * as shamir from "../../web/js/shamir.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));

function detRng(seed) {
  let c = 0n;
  return (n) => {
    let out = Buffer.alloc(0);
    while (out.length < n) {
      const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(c); c += 1n;
      out = Buffer.concat([out, createHash("sha256").update(Buffer.concat([Buffer.from(seed), ctr])).digest()]);
    }
    return new Uint8Array(out.subarray(0, n));
  };
}

test("GF(256) vurma cədvəli Python ilə eynidir", () => {
  for (const [a, b, p] of V.gf) assert.equal(shamir.gfMul(a, b), p);
});

test("Shamir: eyni toxum → Python ilə eyni hissələr", () => {
  const secret = C.b64uD(V.shamir.secret);
  const shares = shamir.split(secret, V.shamir.n, V.shamir.t, detRng(V.shamir.seed));
  assert.deepEqual(shares.map((s) => C.b64u(shamir.shareToBytes(s))), V.shamir.shares);
});

test("Shamir: Python hissələrinin hər 3-lük kombinasiyası JS-də bərpa olunur", () => {
  const all = V.shamir.shares.map((s) => shamir.shareFromBytes(C.b64uD(s)));
  let count = 0;
  for (let i = 0; i < 5; i++) for (let j = i + 1; j < 5; j++) for (let k = j + 1; k < 5; k++) {
    assert.equal(C.b64u(shamir.combine([all[i], all[j], all[k]])), V.shamir.secret);
    count++;
  }
  assert.equal(count, 10);
});

test("PBKDF2 (600 000) + HKDF açar ayrılığı Python ilə eynidir", async () => {
  const mk = await C.masterKey(V.kdf.password, C.b64uD(V.kdf.salt));
  assert.equal(C.b64u(mk), V.kdf.master);
  const k = await C.deriveUserKeys(mk);
  assert.equal(C.b64u(k.authKey), V.kdf.auth);
  assert.equal(C.b64u(k.encKey), V.kdf.enc);
});

test("NFKC normallaşdırma: parçalanmış 'ı' / 'ə' eyni açar verir", async () => {
  const decomposed = V.kdf.password.normalize("NFD");
  const mk = await C.masterKey(decomposed, C.b64uD(V.kdf.salt));
  assert.equal(C.b64u(mk), V.kdf.master);
});

test("İki açarlı kilid KEK = HKDF(S‖R) Python ilə eynidir", async () => {
  const kek = await C.releaseKek(C.b64uD(V.release_kek.S), C.b64uD(V.release_kek.R), V.release_kek.vault);
  assert.equal(C.b64u(kek), V.release_kek.kek);
});

test("Hissə öhdəliyi (commitment) Python ilə eynidir", async () => {
  assert.equal(await C.shareCommitment(V.commitment.vault, C.b64uD(V.commitment.share)), V.commitment.hex);
});

test("Bərpa kodu açarları Python ilə eynidir", async () => {
  const k = await C.recoveryKeys(V.recovery.code.toLowerCase());
  assert.equal(C.b64u(k.authKey), V.recovery.auth);
  assert.equal(C.b64u(k.encKey), V.recovery.enc);
});

test("Doldurma ölçüləri Python ilə eynidir", () => {
  for (const { len, padded_len } of V.pad) assert.equal(C.pad(new Uint8Array(len).fill(120)).length, padded_len);
});

test("Python-un AES-GCM qutusu JS-də açılır", async () => {
  const pt = await C.openSealed(C.b64uD(V.seal.key), V.seal.box, V.seal.aad);
  assert.equal(C.fromUtf8(C.unpad(pt)), V.seal.plaintext);
});

test("Python-un ECIES qutusu JS-də açılır, barmaq izi eynidir", async () => {
  const priv = await C.importPrivatePkcs8(C.b64uD(V.ecies.pkcs8));
  const pt = await C.eciesDecrypt(priv, V.ecies.box, V.ecies.context);
  assert.equal(C.b64u(pt), V.ecies.plaintext);
  assert.equal(await C.fingerprint(C.b64uD(V.ecies.public)), V.ecies.fingerprint);
});

test("ECIES: başqa kontekstlə açmaq alınmır (hissə başqa seyfə köçürülə bilməz)", async () => {
  const priv = await C.importPrivatePkcs8(C.b64uD(V.ecies.pkcs8));
  await assert.rejects(C.eciesDecrypt(priv, V.ecies.box, V.ecies.context.replace("v_test", "v_other")), C.CryptoError);
});
