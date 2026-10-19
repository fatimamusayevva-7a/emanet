// Etibarlı şəxsin paneli: dəvətlər, qoruduğum seyflər, açılma tələbi, hissənin ötürülməsi, seyfi açmaq.
import { h, icon, mount, toast, modal, busy, fmtDate, chip } from "./dom.js";
import * as A from "./api.js";
import * as Sess from "./session.js";

export async function trusteeView(root, go) {
  const [inv, vs] = await Promise.all([A.get("/api/trustee/invitations"), A.get("/api/trustee/vaults")]);
  const again = () => trusteeView(root, go).catch((e) => toast(e.message, "err"));

  const myFp = h("div", { class: "card" }, h("div", { class: "row" }, h("div", { class: "ico" }, icon("shield")),
    h("div", {}, h("h3", {}, "Mənim barmaq izim"),
      h("p", { class: "muted small" }, "Sizi etibarlı şəxs seçən insan zəng edəndə bu 8 qrupu ona oxuyun. O, öz ekranında eyni ardıcıllığı görməlidir."),
      h("div", { class: "fp fp-big", id: "my-fingerprint" }, Sess.S.user.fingerprint))));

  const invitations = inv.invitations.length ? h("div", { class: "card" }, h("h2", {}, "Dəvətlər"),
    h("div", { class: "items" }, ...inv.invitations.map((i) => h("div", { class: "item" }, h("div", { class: "ico" }, icon("mail")),
      h("div", {}, h("div", { class: "t" }, `${i.owner} sizi etibarlı şəxs seçmək istəyir`),
        h("div", { class: "s" }, "Qəbul etsəniz, seyfin açarının bir hissəsi sizin açıq açarınızla şifrələnəcək. Siz təkbaşına seyfi aça bilməyəcəksiniz.")),
      h("div", { class: "row" },
        h("button", { class: "brass small", dataset: { accept: i.owner }, onclick: async () => { await A.post(`/api/trustee/invitations/${i.id}/accept`); toast("Qəbul edildi"); again(); } }, "Qəbul et"),
        h("button", { class: "ghost small", onclick: async () => { await A.post(`/api/trustee/invitations/${i.id}/decline`); again(); } }, "Rədd et")))))) : null;

  const list = vs.vaults.length ? h("div", { class: "grid two", id: "protected-vaults" }, ...vs.vaults.map((v) => vaultCard(v, again)))
    : h("div", { class: "card empty" }, icon("users", 36), h("p", {}, "Hələ heç kim sizi etibarlı şəxs seçməyib."));

  mount(root, h("h1", {}, "Etibar etdiyim insanlar"),
    h("p", { class: "muted" }, "Siz bu insanların rəqəmsal əmanətini qoruyursunuz. Onların seyfinin içini görə bilmirsiniz — yalnız vaxtı çatanda, digər etibarlı şəxslərlə birlikdə."),
    myFp, invitations, h("div", { class: "section-title" }, h("h2", {}, "Qoruduğum seyflər")), list);
}

function vaultCard(v, again) {
  const bar = h("div", { class: "shares-meter", "aria-label": "təsdiqlər" },
    ...Array.from({ length: v.trustees_accepted }, (_, i) => h("span", { class: i < v.approvals ? "on" : "" })));
  let body;
  if (!v.my_x) {
    body = h("p", { class: "muted small" }, "Sahib hələ hissələri paylamayıb.");
  } else if (v.state === "active" || v.state === "reminding" || v.state === "setup") {
    body = h("p", { class: "muted small" }, `Hər şey qaydasındadır. Sahib ${v.inactivity_days} gün cavab verməsə, sizə xəbər verəcəyik.`);
  } else if (v.state === "awaiting") {
    body = h("div", { class: "stack" },
      h("div", { class: "notice info" }, h("strong", {}, `${v.owner} uzun müddətdir cavab vermir`),
        `Açılma üçün ${v.threshold} nəfərin təsdiqi lazımdır. Təsdiqdən sonra sahibə ${v.waiting_days} günlük etiraz müddəti verilir.`),
      bar, h("p", { class: "small muted" }, `Təsdiq: ${v.approvals} / ${v.threshold}`),
      v.i_approved ? h("button", { class: "secondary", onclick: async () => { await A.del(`/api/trustee/vaults/${v.id}/approve`); again(); } }, "Təsdiqimi geri götür")
        : h("button", { class: "brass", id: `approve-${v.id}`, onclick: async () => {
          const ok = await modal("Açılmanı təsdiqləmək", h("p", {}, `${v.owner} ilə əlaqə saxlamağa çalışdınızmı? Təsdiq sahibə və digər etibarlı şəxslərə bildiriləcək və jurnalda qeyd olunacaq.`),
            [{ label: "İmtina", class: "secondary", value: false }, { label: "Təsdiqləyirəm", class: "brass", value: true }]);
          if (!ok) return;
          try { const r = await A.post(`/api/trustee/vaults/${v.id}/approve`); toast(r.state === "pending_release" ? "Hədd tamamlandı — gözləmə müddəti başladı" : "Təsdiqiniz qeyd edildi"); again(); }
          catch (e) { toast(e.message, "err"); }
        } }, "Açılmanı təsdiqlə"));
  } else if (v.state === "pending_release") {
    body = h("div", { class: "notice warn" }, h("strong", {}, "Gözləmə müddəti"),
      `Sahib etiraz etməsə, seyf ${fmtDate(v.release_at)} tarixində açılacaq.`);
  } else {
    body = releasedPanel(v);
  }
  return h("div", { class: "card stack", dataset: { vault: v.id } },
    h("div", { class: "row" }, h("h3", { class: "m0" }, v.owner), chip(v.state)),
    h("p", { class: "small muted" }, v.my_x ? `Sizin hissəniz: #${v.my_x} · Hədd: ${v.threshold} / ${v.trustees_accepted}` : "Hissə yoxdur"),
    body);
}

function releasedPanel(v) {
  const out = h("div", { class: "stack" });
  const status = h("div", { class: "notice danger" }, h("strong", {}, "Seyf açılıb"),
    "Hissənizi digər etibarlı şəxslərə ötürün və ya onlardan gələn hissələrlə seyfi açın. Hissələr bir-birinizin açıq açarı ilə şifrələnir — server onları görmür.");
  const meter = h("div");
  const hand = h("button", { class: "secondary", id: `handoff-${v.id}`, onclick: async (e) => {
    await busy(e.currentTarget, async () => {
      try { const m = await Sess.fetchMaterial(v.id); const r = await Sess.handOff(m); toast(`Hissəniz ${r.count} nəfərə şifrəli ötürüldü`); }
      catch (err) { toast(err.message, "err"); }
    });
  } }, icon("key", 18), "Hissəmi digərlərinə ötür");
  const open = h("button", { class: "brass", id: `open-${v.id}`, onclick: async (e) => {
    await busy(e.currentTarget, async () => {
      try {
        const m = await Sess.fetchMaterial(v.id);
        const r = await Sess.tryOpen(m);
        mount(meter, h("div", { class: "shares-meter" }, ...Array.from({ length: r.need }, (_, i) => h("span", { class: i < r.have ? "on" : "" }))),
          h("p", { class: "small", id: `shares-${v.id}` }, `Hissələr: ${r.have} / ${r.need}`));
        if (!r.opened) { toast(`Hələ ${r.need - r.have} hissə çatmır. Digər etibarlı şəxs hissəsini ötürməlidir.`, "err"); return; }
        showContent(m.owner, r.content);
      } catch (err) { toast(err.message, "err"); }
    });
  } }, icon("lock", 18), "Seyfi aç");
  out.append(status, meter, h("div", { class: "row" }, hand, open));
  return out;
}

function showContent(owner, content) {
  const items = content.items || [];
  modal(`${owner} — əmanət`, h("div", { class: "stack", id: "opened-vault" },
    content.letter ? h("div", { class: "letter" }, content.letter) : null,
    items.length ? h("div", { class: "items" }, ...items.map((it) => h("div", { class: "item" }, h("div", { class: "ico" }, icon("key")),
      h("div", {}, h("div", { class: "t" }, it.title),
        it.username ? h("div", { class: "s" }, it.username) : null,
        it.secret ? h("div", { class: "s" }, h("span", { class: "secret" }, it.secret)) : null,
        it.note ? h("div", { class: "s" }, it.note) : null), h("span")))) : h("p", { class: "muted" }, "Seyfdə qeyd yoxdur."),
    h("p", { class: "hint" }, "Bu məlumat yalnız brauzerinizdə açıldı. Pəncərəni bağlayanda yaddaşdan silinir.")),
  [{ label: "Bağla", class: "secondary" }]);
}
