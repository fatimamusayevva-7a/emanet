// Brauzer kriptoqrafiyasının vahid testləri (Node 22 WebCrypto ilə eyni API).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as C from "../../web/js/crypto.js";
import * as shamir from "../../web/js/shamir.js";

const eq = (a, b) => assert.deepEqual([...a], [...b]);

test("Shamir: 2..7 bütün (n,t) və bütün t-alt çoxluqları", () => {
  let n_checked = 0;
  for (let n = 2; n <= 7; n++) for (let t = 2; t <= n; t++) {
    const s = C.randomBytes(32);
    const sh = shamir.split(s, n, t);
    const idx = [...Array(n).keys()];
    const combos = (arr, k) => k === 0 ? [[]] : arr.flatMap((x, i) => combos(arr.slice(i + 1), k - 1).map((c) => [x, ...c]));
    for (const c of combos(idx, t)) { eq(shamir.combine(c.map((i) => sh[i])), s); n_checked++; }
  }
  assert.equal(n_checked, 219);
});

test("Shamir: t-1 hissə səhv nəticə verir", () => {
  const s = C.randomBytes(32);
  const sh = shamir.split(s, 5, 3);
  assert.notDeepEqual([...shamir.combine(sh.slice(0, 2))], [...s]);
});

test("Shamir: yanlış parametrlər rədd edilir", () => {
  assert.throws(() => shamir.split(new Uint8Array([1]), 2, 3));
  assert.throws(() => shamir.split(new Uint8Array([1]), 3, 1));
  assert.throws(() => shamir.split(new Uint8Array(0), 3, 2));
  const sh = shamir.split(new Uint8Array([1, 2]), 3, 2);
  assert.throws(() => shamir.combine([sh[0], { x: sh[0].x, y: sh[1].y }]));
  assert.throws(() => shamir.shareFromBytes(new Uint8Array([0, 1, 2])));
});

test("GF(256): hər sıfırdan fərqli elementin tərsi var", () => {
  for (let a = 1; a < 256; a++) assert.equal(shamir.gfMul(a, shamir.gfDiv(1, a)), 1);
});

test("AES-GCM: AAD, açar və şifrəmətn dəyişikliyi aşkarlanır", async () => {
  const k = C.randomBytes(32);
  const box = await C.seal(k, C.utf8("salam"), "aad");
  assert.equal(C.fromUtf8(await C.openSealed(k, box, "aad")), "salam");
  await assert.rejects(C.openSealed(k, box, "aad2"), C.CryptoError);
  await assert.rejects(C.openSealed(C.randomBytes(32), box, "aad"), C.CryptoError);
  const ct = C.b64uD(box.ct); ct[0] ^= 1;
  await assert.rejects(C.openSealed(k, { ...box, ct: C.b64u(ct) }, "aad"), C.CryptoError);
  await assert.rejects(C.openSealed(k, { ...box, v: 2 }, "aad"), C.CryptoError);
});

test("Seyf: versiya AAD-dadır (köhnə versiyanı yeni kimi göstərmək olmur)", async () => {
  const k = C.randomBytes(32);
  const box = await C.encryptVault(k, "v_x", 3, { a: 1 });
  assert.deepEqual(await C.decryptVault(k, "v_x", 3, box), { a: 1 });
  await assert.rejects(C.decryptVault(k, "v_x", 4, box));
  await assert.rejects(C.decryptVault(k, "v_y", 3, box));
});

test("ECIES: kontekstə bağlıdır, yanlış alıcı aça bilmir", async () => {
  const a = await C.generateKeypair(), b = await C.generateKeypair();
  const pub = await C.exportPublicRaw(a.publicKey);
  const box = await C.eciesEncrypt(pub, C.utf8("hissə"), "ctx-1");
  assert.equal(C.fromUtf8(await C.eciesDecrypt(a.privateKey, box, "ctx-1")), "hissə");
  await assert.rejects(C.eciesDecrypt(a.privateKey, box, "ctx-2"), C.CryptoError);
  await assert.rejects(C.eciesDecrypt(b.privateKey, box, "ctx-1"), C.CryptoError);
});

test("ECIES: əyri üzərində olmayan nöqtə rədd edilir", async () => {
  const bad = new Uint8Array(65).fill(1); bad[0] = 4;
  await assert.rejects(C.importPublicRaw(bad), C.CryptoError);
  await assert.rejects(C.importPublicRaw(new Uint8Array(33)), C.CryptoError);
});

test("Paylanma → bərpa (2/3), saxta hissə adla tutulur", async () => {
  const kps = await Promise.all([0, 1, 2].map(() => C.generateKeypair()));
  const trustees = await Promise.all(kps.map(async (kp, i) => ({ id: `u_${i}`, public_key: C.b64u(await C.exportPublicRaw(kp.publicKey)) })));
  const dek = C.randomBytes(32), R = C.randomBytes(32);
  const d = await C.buildDistribution({ vaultId: "v_t", dek, releaseKey: R, threshold: 2, trustees });
  const plain = await Promise.all(d.shares.map((s, i) => C.eciesDecrypt(kps[i].privateKey, s.box, C.ctxShare("v_t", `u_${i}`, s.x))));
  const commitments = Object.fromEntries(d.shares.map((s) => [s.x, s.commitment]));
  const got = await C.recoverDek({ vaultId: "v_t", releaseKey: R, wrappedDekRelease: d.wrappedDekRelease, commitments,
    shares: [{ x: 1, bytes: plain[0] }, { x: 3, bytes: plain[2] }] });
  eq(got, dek);
  const forged = plain[1].slice(); forged[5] ^= 0xff;
  await assert.rejects(C.recoverDek({ vaultId: "v_t", releaseKey: R, wrappedDekRelease: d.wrappedDekRelease, commitments,
    shares: [{ x: 1, bytes: plain[0] }, { x: 2, bytes: forged }] }), /saxta və ya korlanmış hissə: #2/);
  await assert.rejects(C.recoverDek({ vaultId: "v_t", releaseKey: C.randomBytes(32), wrappedDekRelease: d.wrappedDekRelease,
    commitments, shares: [{ x: 1, bytes: plain[0] }, { x: 3, bytes: plain[2] }] }), C.CryptoError);
});

test("Doldurma: kiçik məzmunların ölçüsü eynidir, pozulmuş doldurma rədd edilir", () => {
  assert.equal(C.pad(new Uint8Array(1)).length, C.pad(new Uint8Array(3000)).length);
  const p = C.pad(C.utf8("x")); p[p.length - 1] = 1;
  assert.throws(() => C.unpad(p), C.CryptoError);
});

test("Bərpa kodu: format, unikal, normallaşma", async () => {
  const codes = new Set(Array.from({ length: 300 }, () => C.newRecoveryCode()));
  assert.equal(codes.size, 300);
  const c = [...codes][0];
  assert.match(c, /^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){4}$/);
  const a = await C.recoveryKeys(c), b = await C.recoveryKeys(c.toLowerCase().replace(/-/g, " "));
  eq(a.encKey, b.encKey);
  await assert.rejects(C.recoveryKeys("ABCDE"), C.CryptoError);
});

test("base64url: gidiş-dönüş və yanlış simvollar", () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33, 1000, 70000]) { const b = C.randomBytes(n); eq(C.b64uD(C.b64u(b)), b); }
  assert.throws(() => C.b64uD("a+b/"), C.CryptoError);
});

test("İki açarlı kilid: S və ya R dəyişsə KEK dəyişir", async () => {
  const S = C.randomBytes(32), R = C.randomBytes(32);
  const k = C.hex(await C.releaseKek(S, R, "v"));
  assert.notEqual(k, C.hex(await C.releaseKek(C.randomBytes(32), R, "v")));
  assert.notEqual(k, C.hex(await C.releaseKek(S, C.randomBytes(32), "v")));
  await assert.rejects(C.releaseKek(new Uint8Array(5), R, "v"));
});
