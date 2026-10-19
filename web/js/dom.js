// DOM köməkçiləri. innerHTML İSTİFADƏ OLUNMUR: CSP "require-trusted-types-for 'script'"
// hər hansı sətirdən HTML yaratmağı brauzer səviyyəsində bloklayır (DOM XSS-ə qarşı).
// İstifadəçi məlumatı həmişə textContent kimi əlavə olunur.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const SVGNS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  for (const c of children) el.append(c);
  return el;
}

const ICONS = {
  lock: ["M7 11V8a5 5 0 0 1 10 0v3", "M5 11h14v10H5z", "M12 15v2"],
  key: ["M14 7a4 4 0 1 1-3.9 4.9L3 19v2h3v-2h2v-2h2l1.1-1.1A4 4 0 0 1 14 7z", "M15.5 8.5h.01"],
  note: ["M6 3h9l4 4v14H6z", "M14 3v5h5", "M9 13h7", "M9 17h5"],
  user: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M4 21a8 8 0 0 1 16 0"],
  users: ["M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M2 21a7 7 0 0 1 14 0", "M16 3.5a4 4 0 0 1 0 7", "M18 14a7 7 0 0 1 4 7"],
  doc: ["M7 3h7l5 5v13H7z", "M14 3v5h5"],
  heart: ["M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.5-7 10-7 10z"],
  shield: ["M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "M9 12l2 2 4-4"],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 7v5l3 2"],
  mail: ["M3 6h18v12H3z", "M3 7l9 6 9-6"],
  check: ["M5 12l5 5 9-10"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  plus: ["M12 5v14", "M5 12h14"],
  trash: ["M4 7h16", "M9 7V4h6v3", "M6 7l1 13h10l1-13"],
  eye: ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
  pause: ["M8 5v14", "M16 5v14"],
};
export function icon(name, size = 20) {
  return svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
    "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
  ...(ICONS[name] || []).map((d) => svg("path", { d })));
}

export function seal(cls = "seal") {
  return svg("svg", { viewBox: "0 0 64 64", class: cls, "aria-hidden": "true" },
    svg("circle", { cx: 32, cy: 32, r: 29, fill: "#a8792a" }),
    svg("circle", { cx: 32, cy: 32, r: 23, fill: "none", stroke: "#f5f1ea", "stroke-width": 2, "stroke-dasharray": "3 3" }),
    svg("path", { d: "M24 30v-5a8 8 0 0 1 16 0v5", fill: "none", stroke: "#f5f1ea", "stroke-width": 3.2, "stroke-linecap": "round" }),
    svg("rect", { x: 21, y: 29, width: 22, height: 16, rx: 3, fill: "#f5f1ea" }),
    svg("circle", { cx: 32, cy: 36, r: 2.4, fill: "#a8792a" }));
}

export function mount(root, ...nodes) { root.replaceChildren(...nodes.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false)); }

export function toast(msg, kind = "") {
  const t = h("div", { class: `toast ${kind}`, role: "status" }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), kind === "err" ? 6000 : 3500);
}

export function modal(title, body, actions = []) {
  return new Promise((resolve) => {
    const close = (v) => { bg.remove(); resolve(v); };
    const bg = h("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) close(null); } },
      h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
        h("h2", {}, title), body,
        h("div", { class: "actions" }, ...actions.map((a) =>
          h("button", { class: a.class || "", onclick: async () => close(a.value ?? true) }, a.label)))));
    document.body.append(bg);
    const first = bg.querySelector("input, textarea, button");
    if (first) first.focus();
  });
}

export async function busy(btn, fn) {
  const label = [...btn.childNodes];
  btn.disabled = true;
  btn.replaceChildren(h("span", { class: "spinner" }), " Gözləyin…");
  try { return await fn(); } finally { btn.disabled = false; btn.replaceChildren(...label); }
}

// Brauzerlərin "az-AZ" lokal məlumatı natamamdır ("2026 M10 18") — formatı özümüz qururuq: 18.10.2026 20:49 (Bakı)
const fmt = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit",
  minute: "2-digit", hour12: false, timeZone: "Asia/Baku" });
export function fmtDate(ts) {
  if (!ts) return "—";
  const p = Object.fromEntries(fmt.formatToParts(new Date(ts * 1000)).map((x) => [x.type, x.value]));
  return `${p.day}.${p.month}.${p.year} ${p.hour}:${p.minute}`;
}

export function field(labelText, input, hint) {
  return h("div", { class: "field" }, h("label", {}, labelText), input, hint ? h("div", { class: "hint" }, hint) : null);
}

export const STATE_LABEL = {
  setup: "Qurulur", active: "Aktiv", reminding: "Xatırlatma", awaiting: "Etibarlı şəxslər gözlənilir",
  pending_release: "Açılma gözlənilir", released: "Açılıb",
};
export function chip(state, text) { return h("span", { class: `chip ${state}` }, text || STATE_LABEL[state] || state); }
