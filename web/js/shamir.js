// Shamir gizli bölgüsü — GF(2^8), AES çoxhədlisi 0x11B, generator 3.
// `emanet/crypto/shamir.py` ilə bayt-bayt uyğundur (tests/js/crossimpl.test.mjs).
// Bu kod brauzerdə işləyir: hissələr serverə yalnız şifrələnmiş halda gedir.

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    const x2 = ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff;
    x = x2 ^ x;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

export function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

export function gfDiv(a, b) {
  if (b === 0) throw new RangeError("GF(256)-da sıfıra bölmə");
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

function evalPoly(coeffs, x) {
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = gfMul(acc, x) ^ coeffs[i];
  return acc;
}

const defaultRandom = (n) => crypto.getRandomValues(new Uint8Array(n));

/** Sirri n hissəyə böl, istənilən t hissə bərpa edir. Qaytarır: [{x, y: Uint8Array}] */
export function split(secret, n, t, randomBytes = defaultRandom) {
  if (!(secret instanceof Uint8Array) || secret.length === 0) throw new TypeError("sirr boş ola bilməz");
  if (!(Number.isInteger(n) && Number.isInteger(t) && t >= 2 && t <= n && n <= 255)) {
    throw new RangeError("şərt: 2 ≤ t ≤ n ≤ 255");
  }
  const ys = Array.from({ length: n }, () => new Uint8Array(secret.length));
  for (let k = 0; k < secret.length; k++) {
    const coeffs = [secret[k], ...randomBytes(t - 1)];
    for (let i = 0; i < n; i++) ys[i][k] = evalPoly(coeffs, i + 1);
  }
  return ys.map((y, i) => ({ x: i + 1, y }));
}

/** Laqranj interpolyasiyası ilə f(0). t-dən az hissə SƏHV nəticə verir (xəta yox). */
export function combine(shares) {
  if (!Array.isArray(shares) || shares.length < 2) throw new RangeError("ən azı 2 hissə lazımdır");
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new RangeError("təkrarlanan hissə nömrəsi");
  if (xs.some((x) => !(x >= 1 && x <= 255))) throw new RangeError("hissə nömrəsi 1..255");
  const len = shares[0].y.length;
  if (shares.some((s) => s.y.length !== len)) throw new RangeError("hissələrin uzunluğu fərqlidir");

  const basis = xs.map((xj, j) => {
    let num = 1, den = 1;
    xs.forEach((xm, m) => {
      if (m !== j) { num = gfMul(num, xm); den = gfMul(den, xm ^ xj); }
    });
    return gfDiv(num, den);
  });
  const out = new Uint8Array(len);
  for (let k = 0; k < len; k++) {
    let acc = 0;
    shares.forEach((s, j) => { acc ^= gfMul(s.y[k], basis[j]); });
    out[k] = acc;
  }
  return out;
}

export function shareToBytes(s) {
  const out = new Uint8Array(1 + s.y.length);
  out[0] = s.x; out.set(s.y, 1);
  return out;
}

export function shareFromBytes(b) {
  if (b.length < 2) throw new RangeError("hissə çox qısadır");
  if (b[0] === 0) throw new RangeError("x=0 hissəsi qadağandır");
  return { x: b[0], y: b.slice(1) };
}
