// Operator (istifadəçi idarəsi, demo saatı) və auditor (jurnal, zəncirin yoxlanması) panelləri.
import { h, mount, toast, fmtDate, chip, busy, icon } from "./dom.js";
import * as A from "./api.js";
import * as Sess from "./session.js";

export async function adminView(root) {
  const [u, ev] = await Promise.all([A.get("/api/admin/users"), A.get("/api/admin/security-events")]);
  const demo = Sess.S.demo ? h("div", { class: "card stack", id: "demo-panel" }, h("h2", {}, "Demo saatı"),
    h("p", { class: "muted small" }, "Yalnız EMANET_DEMO_MODE=1 olanda mövcuddur (istehsalda konfiqurasiya bunu qadağan edir). Komissiya qarşısında aylar keçməsini simulyasiya edir və planlaşdırıcını işə salır."),
    h("div", { class: "row" }, ...[7, 30, 31, 60].map((d) => h("button", { class: "secondary", id: `demo-${d}`, onclick: async (e) => {
      await busy(e.currentTarget, async () => {
        const r = await A.post("/api/demo/advance", { days: d });
        toast(`+${d} gün. Saat sürüşməsi: ${r.offset_days} gün. Məktub: ${r.tick.emails_sent}`);
        adminView(root);
      });
    } }, icon("clock", 18), `+${d} gün`)))) : null;

  mount(root, h("h1", {}, "Operator paneli"),
    h("p", { class: "muted" }, "Operator istifadəçiləri idarə edir, amma seyfləri aça, açılmanı məcbur edə və ya audit jurnalını oxuya bilməz (vəzifələrin bölünməsi)."),
    demo,
    h("div", { class: "card" }, h("h2", {}, "İstifadəçilər"), h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["Ad", "E-poçt", "Rol", "MFA", "Seyf", "Status", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, ...u.users.map((r) => h("tr", {},
        h("td", {}, r.display_name), h("td", {}, r.email), h("td", {}, r.role), h("td", {}, r.totp_enabled ? "✓" : "—"),
        h("td", {}, r.vault_state ? chip(r.vault_state) : "—"), h("td", {}, r.status),
        h("td", {}, r.id === Sess.S.user.id ? "" : h("button", { class: "ghost small", onclick: async () => {
          try { await A.post(`/api/admin/users/${r.id}/status`, { status: r.status === "active" ? "suspended" : "active" }); adminView(root); }
          catch (e) { toast(e.message, "err"); }
        } }, r.status === "active" ? "Dayandır" : "Bərpa et")))))))),
    h("div", { class: "card" }, h("h2", {}, "Təhlükəsizlik hadisələri"), eventsTable(ev.events)));
}

function eventsTable(events) {
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ...["Vaxt", "Növ", "Aktor", "IP"].map((x) => h("th", {}, x)))),
    h("tbody", {}, ...events.map((e) => h("tr", {}, h("td", { class: "mono" }, fmtDate(e.ts)), h("td", {}, e.kind),
      h("td", { class: "mono small" }, e.actor || "—"), h("td", { class: "mono small" }, e.ip || "—"))))));
}

export async function auditView(root) {
  const [log, ver] = await Promise.all([A.get("/api/audit"), A.get("/api/audit/verify")]);
  mount(root, h("h1", {}, "Audit jurnalı"),
    h("div", { class: `notice ${ver.intact ? "ok" : "danger"}`, id: "audit-verdict" },
      h("strong", {}, ver.intact ? "Zəncir bütövdür" : "ZƏNCİR QIRILIB"),
      ver.intact ? `${ver.entries} qeydin hamısının HMAC-SHA256 zənciri yoxlanıldı.` : `İlk pozulmuş qeyd: #${ver.first_broken_index}`),
    h("div", { class: "card table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["#", "Vaxt", "Hərəkət", "Aktor", "Seyf", "Heş"].map((x) => h("th", {}, x)))),
      h("tbody", {}, ...log.entries.map((e) => h("tr", {}, h("td", {}, e.id), h("td", { class: "mono small" }, fmtDate(e.ts)),
        h("td", {}, e.action), h("td", { class: "mono small" }, (e.actor || "—").slice(0, 14)),
        h("td", { class: "mono small" }, (e.vault_id || "—").slice(0, 12)), h("td", { class: "mono small" }, e.entry_hash.slice(0, 12) + "…")))))));
}

export async function mailboxView(root) {
  const r = await A.get("/api/demo/outbox");
  mount(root, h("h1", {}, "Poçt qutusu (demo)"),
    h("p", { class: "muted" }, "Demo rejimində real e-poçt göndərilmir — sizə gələn məktublar burada görünür. İstehsalda bunlar Amazon SES ilə göndərilir."),
    r.messages.length ? h("div", { class: "items", id: "mailbox" }, ...r.messages.map((m) => h("div", { class: "card stack" },
      h("div", { class: "row" }, h("b", {}, m.subject), h("span", { class: "muted small" }, fmtDate(m.created_at))),
      h("p", { class: "small" }, ...linkify(m.body)))))
      : h("div", { class: "card empty" }, icon("mail", 36), h("p", {}, "Məktub yoxdur.")));
}

function linkify(text) {
  const parts = text.split(/(https?:\/\/\S+)/g);
  return parts.map((p) => (/^https?:\/\//.test(p) ? h("a", { href: p, rel: "noopener noreferrer" }, p) : p));
}
