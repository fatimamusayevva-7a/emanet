// Əmanət — tətbiq qabığı və marşrutlaşdırma.
import { h, seal, mount, toast } from "./dom.js";
import * as Sess from "./session.js";
import { landing, lockScreen, recoverView } from "./views-auth.js";
import { ownerView, resetOwnerState } from "./views-owner.js";
import { trusteeView } from "./views-trustee.js";
import { adminView, auditView, mailboxView } from "./views-admin.js";

const root = document.getElementById("root");

function go(hash) {
  if (location.hash === hash) route(); else location.hash = hash;
}

function shell(active) {
  const S = Sess.S;
  const links = [["#/vault", "Mənim seyfim"], ["#/trustee", "Etibar etdiyim insanlar"]];
  if (S.demo) links.push(["#/mail", "Poçt qutusu"]);
  if (S.user.role === "operator") links.push(["#/admin", "Operator"]);
  if (S.user.role === "auditor") links.splice(0, links.length, ["#/audit", "Audit"]);
  const content = h("main", { id: "view" });
  mount(root,
    S.demo ? h("div", { class: "demo-ribbon" }, "DEMO REJİMİ — saat sürüşdürülə bilər, məktublar “Poçt qutusu”na düşür") : null,
    h("header", { class: "topbar" },
      h("a", { href: "#/vault", class: "brand" }, seal("seal"), "Əmanət"),
      h("nav", { class: "nav" }, ...links.map(([href, label]) => h("a", { href, class: href === active ? "active" : "" }, label))),
      h("div", { class: "spacer" }),
      h("div", { class: "who" }, h("span", { id: "who-name" }, S.user.display_name),
        h("button", { class: "ghost small", id: "btn-logout", onclick: async () => { await Sess.logout(); resetOwnerState(); go("#/"); } }, "Çıxış"))),
    content,
    h("footer", { class: "foot" }, "Əmanət · şifrələmə brauzerinizdə aparılır · ", h("a", { href: "/api/integrity" }, "kodun bütövlük manifesti")));
  return content;
}

async function route() {
  const hash = location.hash || "#/";
  try {
    if (hash === "#/recover") return recoverView(root, go);
    if (!Sess.S.user) {
      const ok = await Sess.resume();
      if (!ok) return landing(root, go);
    }
    if (!Sess.S.priv) return lockScreen(root, go);
    const role = Sess.S.user.role;
    let page = ["#/vault", "#/trustee", "#/admin", "#/audit", "#/mail"].includes(hash) ? hash : "#/vault";
    if (role === "auditor") page = "#/audit";
    if (page === "#/admin" && role !== "operator") page = "#/vault";
    const view = shell(page);
    view.append(h("p", { class: "muted" }, "Yüklənir…"));
    if (page === "#/vault") await ownerView(view, go);
    else if (page === "#/trustee") await trusteeView(view, go);
    else if (page === "#/admin") await adminView(view, go);
    else if (page === "#/audit") await auditView(view, go);
    else if (page === "#/mail") await mailboxView(view, go);
  } catch (e) {
    if (e.status === 401) { Sess.clear(); resetOwnerState(); return landing(root, go); }
    console.error(e);
    toast(e.message || "Xəta baş verdi", "err");
  }
}

window.addEventListener("hashchange", route);
// Səhifə gizlədilib 15 dəqiqə keçibsə, açarları yaddaşdan sil (çiyin üstündən baxma / unudulmuş tab)
let hiddenAt = 0;
document.addEventListener("visibilitychange", () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (hiddenAt && Date.now() - hiddenAt > 15 * 60 * 1000 && Sess.S.priv) { Sess.S.priv = null; Sess.S.encKey = null; Sess.S.dek = null; resetOwnerState(); route(); }
});
route();
