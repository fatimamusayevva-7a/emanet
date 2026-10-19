// Sahibin paneli: "sağam" vəziyyəti, seyfin məzmunu, etibarlı şəxslər, parametrlər, fəaliyyət.
import { h, svg, icon, mount, toast, modal, busy, field, fmtDate, chip, STATE_LABEL } from "./dom.js";
import * as A from "./api.js";
import * as Sess from "./session.js";

const ACTION_LABEL = {
  "vault.created": "Seyf yaradıldı", "vault.content_saved": "Məzmun yadda saxlanıldı", "vault.checkin": "“Sağam” təsdiqi",
  "vault.checkin_link": "E-poçt linki ilə “sağam”", "vault.settings_changed": "Parametrlər dəyişdi",
  "vault.distributed": "Hissələr paylandı", "vault.paused": "Pauza", "vault.unpaused": "Pauza bitdi",
  "vault.release_key_read_by_owner": "Zaman kilidi açarı oxundu (sahib)", "trustee.invited": "Etibarlı şəxs dəvət olundu",
  "trustee.accepted": "Dəvət qəbul edildi", "trustee.declined": "Dəvət rədd edildi", "trustee.removed": "Etibarlı şəxs silindi",
  "trustee.fingerprint_verified": "Barmaq izi təsdiqləndi", "release.approved": "Açılma təsdiqləndi",
  "release.approval_withdrawn": "Təsdiq geri götürüldü", "release.premature_attempt": "Vaxtından əvvəl açılma cəhdi (rədd edildi)",
  "release.cancelled_by_owner": "Açılma sahib tərəfindən ləğv edildi", "release.material_fetched": "Açılmış material alındı",
  "release.share_handed_off": "Hissə ötürüldü",
};
const actionLabel = (a) => ACTION_LABEL[a] || (a.startsWith("switch.") ? "Vəziyyət: " + a.slice(7).split("->").map((s) => STATE_LABEL[s] || s).join(" → ") : a);

const TYPES = { account: ["Hesab", "key"], note: ["Qeyd", "note"], doc: ["Sənəd yeri", "doc"], wish: ["Arzu / göstəriş", "heart"] };

let state = { vault: null, content: null, version: 0, dirty: false, tab: "content" };

export async function ownerView(root, go) {
  if (!Sess.S.vaultId) {
    mount(root, h("div", { class: "card empty" }, icon("lock", 36), h("p", {}, "Sizin hələ seyfiniz yoxdur."),
      h("p", { class: "small" }, "Seyf qeydiyyat zamanı yaradılır. Bu hesab yalnız etibarlı şəxs kimi istifadə olunur."),
      h("a", { href: "#/trustee" }, "Etibar etdiyim insanlar →")));
    return;
  }
  state.vault = await Sess.loadVault();
  if (!state.content) {
    const c = await Sess.loadContent();
    state.content = c.content; state.version = c.version; state.dirty = false;
  }
  render(root, go);
}

function refresh(root, go) { return ownerView(root, go).catch((e) => toast(e.message, "err")); }

function render(root, go) {
  if (!state.vault || !state.content) return;   // istifadəçi çıxış edib (yarış vəziyyəti)
  const st = state.vault.status;
  const tabs = [["content", "Seyfin məzmunu"], ["trustees", "Etibarlı şəxslər"], ["settings", "Parametrlər"], ["activity", "Fəaliyyət"]];
  const tabBar = h("div", { class: "tabs", role: "tablist" }, ...tabs.map(([k, label]) =>
    h("button", { class: state.tab === k ? "on" : "", id: `tab-${k}`, onclick: () => { state.tab = k; render(root, go); } }, label)));
  const body = h("div");
  ({ content: contentTab, trustees: trusteesTab, settings: settingsTab, activity: activityTab })[state.tab](body, root, go);
  mount(root, heroCard(st, root, go), setupChecklist(root, go), h("div", { class: "card" }, tabBar, body));
}

// ----------------------------------------------------------------- hero
function ring(st) {
  const pending = st.state === "pending_release";
  const total = pending ? st.waiting_days : (st.inactivity_days || 60);
  const left = st.state === "setup" ? total : st.state === "released" ? 0
    : pending ? (st.release_in_days ?? 0) : st.days_until_awaiting;
  const frac = Math.max(0, Math.min(1, left / total));
  const C = 2 * Math.PI * 88;
  const cls = st.state === "pending_release" || st.state === "awaiting" || st.state === "released" ? "alert"
    : st.state === "reminding" ? "warn" : "";
  return h("div", { class: `ring ${cls}` },
    svg("svg", { viewBox: "0 0 200 200" },
      svg("circle", { class: "track", cx: 100, cy: 100, r: 88, fill: "none", "stroke-width": 14 }),
      svg("circle", { class: "bar", cx: 100, cy: 100, r: 88, fill: "none", "stroke-width": 14, "stroke-linecap": "round",
        "stroke-dasharray": C, "stroke-dashoffset": C * (1 - frac) })),
    h("div", { class: "center" }, h("div", { class: "big", id: "days-left" }, String(Math.ceil(left))),
      h("div", { class: "lbl" }, pending ? "gün sonra açılır" : "gün qalıb")));
}

function stepper(st) {
  const order = ["active", "reminding", "awaiting", "pending_release", "released"];
  const labels = ["Aktiv", "Xatırlatma", "Tələb oluna bilər", "Gözləmə müddəti", "Açılıb"];
  const idx = order.indexOf(st.state);
  return h("div", { class: "steps", "aria-label": "Vəziyyət mərhələləri" },
    ...labels.map((l, i) => h("div", { class: i < idx ? "done" : i === idx ? "now" : "" }, l)));
}

function heroCard(st, root, go) {
  const alive = h("button", { class: "alive", id: "btn-alive", onclick: async (e) => {
    await busy(e.currentTarget, async () => {
      const r = await A.post("/api/vault/checkin");
      toast(r.state === "active" ? "Qeyd edildi. Sayğac sıfırlandı." : "Qeyd edildi");
      await refresh(root, go);
    });
  } }, icon("check", 22), "Sağam, hər şey qaydasındadır");

  let headline, text;
  if (st.state === "setup") {
    headline = "Seyf hələ qorunmur";
    text = "Etibarlı şəxsləri əlavə edin, barmaq izlərini təsdiqləyin və hissələri paylayın — bundan sonra “sağam” sayğacı işə düşəcək.";
  } else if (st.state === "pending_release") {
    headline = "Diqqət: seyfin açılması gözlənilir";
    text = `Etibarlı şəxslər açılmanı təsdiqləyib. ${fmtDate(st.release_at)} tarixində seyf açılacaq. Bu səhvdirsə, “Sağam” düyməsini basın — proses dərhal ləğv olunacaq.`;
  } else if (st.state === "awaiting") {
    headline = "Uzun müddətdir cavab vermirsiniz";
    text = "Etibarlı şəxslər artıq açılma tələb edə bilər. Hər şey qaydasındadırsa, “Sağam” düyməsini basın.";
  } else if (st.state === "released") {
    headline = "Seyf açılıb";
    text = "Seyf etibarlı şəxslər üçün açılıb. Yeni seyf qurmaq üçün köhnəsini silin və yenidən yaradın.";
  } else {
    headline = st.state === "reminding" ? "Sizə xatırlatma göndərmişik" : "Hər şey qaydasındadır";
    text = `Son aktivlik: ${fmtDate(st.last_activity_at)}. ${st.inactivity_days} gün cavab verməsəniz, etibarlı şəxslər açılmanı tələb edə biləcək; sonra ${st.waiting_days} günlük gözləmə müddəti başlayır.`;
  }
  const pausedNote = st.paused_until
    ? h("div", { class: "notice info small" }, `Pauza: ${fmtDate(st.paused_until)} tarixinə qədər xatırlatma göndərilmir.`) : null;
  return h("div", { class: "card" }, h("div", { class: "hero" }, ring(st),
    h("div", { class: "stack" },
      h("div", { class: "row" }, chip(st.state), h("span", { class: "muted small" }, `Hədd: ${st.threshold ? `${st.threshold} / ${st.trustees_accepted}` : "—"}`)),
      h("h1", { id: "hero-title" }, headline), h("p", { class: "muted" }, text), pausedNote,
      st.state !== "released" && st.state !== "setup" ? alive : null)),
  st.state !== "setup" ? stepper(st) : null);
}

function setupChecklist(root, go) {
  const v = state.vault, st = v.status;
  if (st.state !== "setup" && v.trustees.every((t) => t.status !== "accepted" || t.has_share)) return null;
  const accepted = v.trustees.filter((t) => t.status === "accepted");
  const steps = [
    [state.content.items.length > 0 || state.content.letter, "Seyfə ən azı bir qeyd əlavə edin"],
    [accepted.length >= 2, "Ən azı 2 etibarlı şəxs dəvəti qəbul etsin"],
    [accepted.length >= 2 && accepted.every((t) => t.fingerprint_verified), "Hər birinin barmaq izini telefonda müqayisə edin"],
    [st.state !== "setup" && accepted.every((t) => t.has_share), "Hissələri paylayın"],
  ];
  return h("div", { class: "card" }, h("h3", {}, st.state === "setup" ? "Qurulma addımları" : "Paylanmanı yeniləmək lazımdır"),
    h("div", { class: "items" }, ...steps.map(([done, label], i) => h("div", { class: "item" },
      h("div", { class: "ico" }, done ? icon("check") : String(i + 1)), h("div", { class: "t" }, label),
      done ? chip("ok", "hazır") : chip("invited", "gözləyir")))));
}

// ----------------------------------------------------------------- məzmun
function contentTab(body, root, go) {
  const items = state.content.items;
  const save = h("button", { class: "brass", id: "btn-save", disabled: !state.dirty, onclick: async (e) => {
    await busy(e.currentTarget, async () => {
      try {
        await Sess.saveContent(state.version + 1, state.content);
        state.version += 1; state.dirty = false;
        toast("Brauzerdə şifrələndi və yadda saxlanıldı");
        await refresh(root, go);
      } catch (err) {
        if (err.code === "version_conflict") { state.content = null; toast("Seyf başqa yerdə dəyişib — yenidən yükləndi", "err"); await refresh(root, go); }
        else toast(err.message, "err");
      }
    });
  } }, icon("lock", 18), state.dirty ? "Şifrələ və yadda saxla" : "Yadda saxlanılıb");

  const list = items.length ? h("div", { class: "items", id: "items" }, ...items.map((it, i) => {
    const [label, ic] = TYPES[it.type] || TYPES.note;
    const secretEl = h("span", { class: "secret" }, "••••••••");
    let shown = false;
    return h("div", { class: "item" }, h("div", { class: "ico" }, icon(ic)),
      h("div", {}, h("div", { class: "t" }, it.title), h("div", { class: "s" }, label, it.username ? ` · ${it.username}` : "",
        it.secret ? " · " : "", it.secret ? secretEl : "")),
      h("div", { class: "row" },
        it.secret ? h("button", { class: "ghost small", title: "Göstər", onclick: () => { shown = !shown; secretEl.textContent = shown ? it.secret : "••••••••"; } }, icon("eye", 16)) : null,
        h("button", { class: "ghost small", onclick: () => editItem(it, i, root, go) }, "Düzəlt"),
        h("button", { class: "ghost small", title: "Sil", onclick: () => { items.splice(i, 1); state.dirty = true; render(root, go); } }, icon("trash", 16))));
  })) : h("div", { class: "empty" }, icon("lock", 36), h("p", {}, "Seyf boşdur."),
    h("p", { class: "small" }, "Bank, e-poçt, bulud hesabları, sənədlərin harada saxlandığı, ailənizə göstərişlər…"));

  const letter = h("textarea", { id: "letter", placeholder: "Əzizlərim, bu məktubu oxuyursunuzsa…", rows: 6 });
  letter.value = state.content.letter || "";
  letter.oninput = () => { state.content.letter = letter.value; if (!state.dirty) { state.dirty = true; save.disabled = false; save.replaceChildren(icon("lock", 18), "Şifrələ və yadda saxla"); } };

  mount(body,
    h("div", { class: "section-title" }, h("h2", {}, "Qeydlər"), h("div", { class: "row" },
      h("button", { class: "secondary", id: "btn-add-item", onclick: () => editItem(null, -1, root, go) }, icon("plus", 18), "Əlavə et"), save)),
    list,
    h("div", { class: "section-title" }, h("h2", {}, "Etibarlı şəxslərə məktub")),
    letter,
    h("p", { class: "hint" }, `Hər şey brauzerinizdə AES-256-GCM ilə şifrələnir. Server yalnız ${Math.max(4, Math.round((state.vault.status.blob_size || 0) / 1024))} KiB-lıq doldurulmuş şifrəmətn görür — qeydlərin sayı və uzunluğu gizli qalır. Versiya: ${state.version}.`));
}

async function editItem(it, idx, root, go) {
  const type = h("select", { id: "item-type" }, ...Object.entries(TYPES).map(([k, [l]]) => h("option", { value: k }, l)));
  type.value = it?.type || "account";
  const title = h("input", { type: "text", id: "item-title", value: it?.title || "", placeholder: "Məs.: Kapital Bank internet bankinq" });
  const user = h("input", { type: "text", id: "item-user", value: it?.username || "", autocomplete: "off" });
  const secret = h("input", { type: "text", id: "item-secret", value: it?.secret || "", autocomplete: "off", class: "mono" });
  const note = h("textarea", { id: "item-note", rows: 3 }); note.value = it?.note || "";
  const ok = await modal(it ? "Qeydi düzəlt" : "Yeni qeyd", h("div", {},
    field("Növ", type), field("Başlıq", title), field("İstifadəçi adı / hesab", user),
    field("Parol / PIN / gizli məlumat", secret), field("Qeyd", note, "Məs.: “Sənədlər qəhvəyi qovluqdadır, ikinci rəfdə”.")),
  [{ label: "İmtina", class: "secondary", value: false }, { label: "Əlavə et", class: "brass", value: true }]);
  if (!ok) return;
  if (!title.value.trim()) return toast("Başlıq boş ola bilməz", "err");
  const rec = { id: it?.id || crypto.randomUUID(), type: type.value, title: title.value.trim(), username: user.value.trim(),
    secret: secret.value, note: note.value, updated: Date.now() };
  if (idx >= 0) state.content.items[idx] = rec; else state.content.items.push(rec);
  state.dirty = true;
  render(root, go);
}

// ----------------------------------------------------------------- etibarlı şəxslər
function trusteesTab(body, root, go) {
  const v = state.vault;
  const email = h("input", { type: "email", id: "invite-email", placeholder: "etibarli@example.az" });
  const invite = h("form", { class: "row", onsubmit: async (e) => {
    e.preventDefault();
    try { await A.post("/api/vault/trustees", { email: email.value.trim().toLowerCase() }); toast("Dəvət göndərildi"); await refresh(root, go); }
    catch (err) { toast(err.message, "err"); }
  } }, h("div", { class: "grow" }, email), h("button", { type: "submit", id: "btn-invite" }, icon("plus", 18), "Dəvət et"));

  const accepted = v.trustees.filter((t) => t.status === "accepted");
  const rows = v.trustees.length ? h("div", { class: "items", id: "trustee-list" }, ...v.trustees.map((t) =>
    h("div", { class: "item" }, h("div", { class: "ico" }, icon("user")),
      h("div", {}, h("div", { class: "t" }, t.display_name || t.email), h("div", { class: "s" }, t.email),
        t.fingerprint ? h("div", { class: "s" }, "Barmaq izi: ", h("span", { class: "mono" }, t.fingerprint)) : null),
      h("div", { class: "row" },
        chip(t.status, { invited: "Dəvət edilib", accepted: "Qəbul edib", declined: "Rədd edib" }[t.status]),
        t.status === "accepted" && !t.fingerprint_verified ? h("button", { class: "small", dataset: { verify: t.email },
          onclick: () => verifyFp(t, root, go) }, "Barmaq izini yoxla") : null,
        t.fingerprint_verified ? chip("ok", "Yoxlanılıb") : null,
        t.approved ? chip("pending_release", "Açılmanı təsdiqləyib") : null,
        h("button", { class: "ghost small", title: "Sil", onclick: async () => {
          const ok = await modal("Etibarlı şəxsi silmək", h("p", {}, `${t.display_name || t.email} silinsin? Hissəsi varsa, hissələr yenidən paylanmalıdır.`),
            [{ label: "İmtina", class: "secondary", value: false }, { label: "Sil", class: "danger", value: true }]);
          if (!ok) return;
          const r = await A.del(`/api/vault/trustees/${t.id}`);
          toast(r.redistribution_required ? "Silindi. Hissələri yenidən paylayın." : "Silindi");
          await refresh(root, go);
        } }, icon("trash", 16)))))) : h("div", { class: "empty" }, icon("users", 36), h("p", {}, "Hələ etibarlı şəxs yoxdur."));

  const n = accepted.length;
  const thr = h("select", { id: "threshold" }, ...Array.from({ length: Math.max(0, n - 1) }, (_, i) => i + 2).map((k) =>
    h("option", { value: k }, `${k} / ${n}`)));
  thr.value = String(v.status.threshold && v.status.threshold <= n ? v.status.threshold : Math.min(2, n));
  const allVerified = n >= 2 && accepted.every((t) => t.fingerprint_verified);
  const dist = h("button", { class: "brass", id: "btn-distribute", disabled: !allVerified || ["pending_release", "released"].includes(v.status.state),
    onclick: async (e) => {
      await busy(e.currentTarget, async () => {
        try {
          if (state.dirty) { await Sess.saveContent(state.version + 1, state.content); state.version += 1; state.dirty = false; }
          await Sess.distribute(Number(thr.value), accepted);
          toast(`Hissələr paylandı: ${thr.value} / ${n}`);
          await refresh(root, go);
        } catch (err) { toast(err.message, "err"); }
      });
    } }, icon("key", 18), v.has_distribution ? "Hissələri yenidən payla" : "Hissələri payla");

  mount(body,
    h("p", { class: "muted" }, "Etibarlı şəxslər seyfinizi təkbaşına aça bilməz. Açar Shamir sxemi ilə bölünür: seçdiyiniz sayda insan birləşməlidir, üstəlik siz uzun müddət cavab verməməlisiniz."),
    invite, h("div", { class: "gap16" }), rows,
    h("div", { class: "section-title" }, h("h2", {}, "Hədd və paylanma")),
    n < 2 ? h("div", { class: "notice warn" }, h("strong", {}, "Ən azı 2 nəfər lazımdır"), "Dəvəti qəbul etmiş etibarlı şəxslərin sayı: " + n)
      : h("div", { class: "stack" },
        h("div", { class: "row" }, h("label", { for: "threshold", class: "m0" }, "Seyfi açmaq üçün neçə nəfər birləşməlidir?"), thr),
        h("p", { class: "hint" }, "Tövsiyə: 3 nəfərdən 2-si. Biri əlçatmaz olsa da seyf açıla bilər, amma heç kim təkbaşına aça bilməz."),
        !allVerified ? h("div", { class: "notice warn" }, h("strong", {}, "Əvvəlcə barmaq izlərini yoxlayın"),
          "Hər etibarlı şəxsə zəng edin və onun ekranındakı barmaq izini buradakı ilə müqayisə edin. Bu, serverin saxta açar qoymasının (MITM) qarşısını alır.") : null,
        dist));
}

async function verifyFp(t, root, go) {
  const ok = h("input", { type: "checkbox", id: "fp-ack" });
  const r = await modal("Barmaq izini müqayisə edin", h("div", { class: "stack" },
    h("p", {}, `${t.display_name}-a zəng edin və ya üz-üzə görüşün. Ondan “Etibar etdiyim insanlar” bölməsində öz barmaq izini oxumasını xahiş edin.`),
    h("div", { class: "fp fp-big" }, t.fingerprint),
    h("label", { class: "check" }, ok, h("span", {}, "Bütün 8 qrup tam eynidir."))),
  [{ label: "İmtina", class: "secondary", value: false }, { label: "Təsdiqlə", class: "brass", value: true }]);
  if (!r) return;
  if (!ok.checked) return toast("Uyğunluğu təsdiqləyin", "err");
  try { await A.post(`/api/vault/trustees/${t.id}/verify`, { fingerprint: t.fingerprint }); toast("Təsdiqləndi"); await refresh(root, go); }
  catch (err) { toast(err.message, "err"); }
}

// ----------------------------------------------------------------- parametrlər
function settingsTab(body, root, go) {
  const st = state.vault.status;
  const iv = h("input", { type: "number", id: "set-interval", min: 7, max: 90, value: st.checkin_interval_days });
  const ia = h("input", { type: "number", id: "set-inactivity", min: 14, max: 365, value: st.inactivity_days });
  const wd = h("input", { type: "number", id: "set-waiting", min: 3, max: 30, value: st.waiting_days });
  const pd = h("input", { type: "number", id: "set-pause", min: 0, max: 90, value: 0 });
  mount(body, h("div", { class: "grid two" },
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      try { await A.patch("/api/vault/settings", { checkin_interval_days: +iv.value, inactivity_days: +ia.value, waiting_days: +wd.value }); toast("Yadda saxlanıldı"); await refresh(root, go); }
      catch (err) { toast(err.message, "err"); }
    } }, h("h3", {}, "“Sağam” yoxlaması"),
    field("Xatırlatma neçə gündən sonra başlasın?", iv, "7–90 gün. Sonra hər 7 gündən bir e-poçt gəlir."),
    field("Neçə gün cavab olmasa, etibarlı şəxslər tələb edə bilsin?", ia, "14–365 gün; xatırlatma müddətindən ən azı 7 gün çox."),
    field("Təsdiqdən sonra gözləmə (etiraz) müddəti", wd, "3–30 gün. Bu müddətdə istənilən aktivliyiniz açılmanı ləğv edir."),
    h("button", { type: "submit" }, "Yadda saxla")),
    h("div", { class: "stack" },
      h("form", { class: "stack", onsubmit: async (e) => {
        e.preventDefault();
        try { await A.post("/api/vault/pause", { days: +pd.value }); toast(+pd.value ? "Pauza aktivdir" : "Pauza bitdi"); await refresh(root, go); }
        catch (err) { toast(err.message, "err"); }
      } }, h("h3", {}, "Uzun səfər və ya xəstəxana"), field("Pauza (gün)", pd, "Ən çox 90 gün. 0 — pauzanı ləğv edir."),
      h("button", { class: "secondary", type: "submit" }, icon("pause", 18), "Pauza et")),
      h("div", { class: "notice danger stack" }, h("strong", {}, "Seyfi məhv et (crypto-shredding)"),
        h("p", { class: "small" }, "Zaman kilidi açarı və bütün sarınmış açarlar silinir. Ehtiyat nüsxələrdə qalan şifrəmətn də riyazi olaraq oxunmaz olur. Geri qaytarmaq mümkün deyil."),
        h("button", { class: "danger", onclick: async () => {
          const inp = h("input", { type: "text", id: "confirm-delete", placeholder: "SİL" });
          const ok = await modal("Seyfi həmişəlik silmək", h("div", {}, h("p", {}, "Təsdiq üçün böyük hərflərlə SİL yazın."), inp),
            [{ label: "İmtina", class: "secondary", value: false }, { label: "Məhv et", class: "danger", value: true }]);
          if (!ok || inp.value !== "SİL") return;
          await A.del("/api/vault", { confirm: "SİL" });
          Sess.S.vaultId = null; Sess.S.dek = null; state.content = null;
          toast("Seyf məhv edildi"); go("#/trustee");
        } }, icon("trash", 18), "Seyfi məhv et")))));
}

// ----------------------------------------------------------------- fəaliyyət
async function activityTab(body) {
  mount(body, h("p", { class: "muted" }, "Yüklənir…"));
  const r = await A.get("/api/vault/activity");
  mount(body, h("p", { class: "muted small" }, "Seyfinizlə bağlı hər hadisə — o cümlədən etibarlı şəxslərin hər hərəkəti — burada görünür. Jurnal HMAC zənciri ilə qorunur: bir qeydin dəyişdirilməsi zənciri qırır."),
    h("ul", { class: "timeline", id: "activity" }, ...r.events.map((e) => h("li", {},
      h("time", {}, fmtDate(e.ts)), h("div", {}, h("b", {}, actionLabel(e.action)), " · ", h("span", { class: "muted" }, e.actor || "sistem"))))));
}

export function resetOwnerState() { state = { vault: null, content: null, version: 0, dirty: false, tab: "content" }; }
