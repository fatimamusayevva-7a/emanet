// Giriş, qeydiyyat, kilid ekranı, bərpa kodu.
import { h, seal, field, toast, busy, mount } from "./dom.js";
import * as Sess from "./session.js";
import { ApiError } from "./api.js";

const COMMON = ["password", "123456789012", "qwertyuiop12", "parol1234567", "azerbaycan123", "baku12345678"];

export function passwordProblems(pw, email = "") {
  const p = [];
  if (pw.length < 12) p.push("ən azı 12 simvol");
  if (COMMON.includes(pw.toLowerCase())) p.push("çox yayılmış parol");
  const local = email.split("@")[0];
  if (local.length >= 3 && pw.toLowerCase().includes(local.toLowerCase())) p.push("e-poçt adını ehtiva etməsin");
  return p;
}

function errText(e) {
  if (e instanceof ApiError) return e.message;
  return e?.message || String(e);
}

export function landing(root, go) {
  const tabLogin = h("button", { class: "on", type: "button" }, "Daxil ol");
  const tabReg = h("button", { type: "button" }, "Hesab yarat");
  const body = h("div");
  const show = (which) => {
    tabLogin.classList.toggle("on", which === "login");
    tabReg.classList.toggle("on", which === "reg");
    mount(body, which === "login" ? loginForm(go) : registerForm(go));
  };
  tabLogin.onclick = () => show("login");
  tabReg.onclick = () => show("reg");
  show(location.hash === "#/register" ? "reg" : "login");

  mount(root, h("div", { class: "auth" },
    h("div", { class: "lead" }, seal("seal"),
      h("h1", {}, "Əmanət"),
      h("p", { class: "muted" }, "Rəqəmsal həyatınızın açarlarını etibar etdiyiniz insanlara — yalnız lazım olanda.")),
    h("div", { class: "card" }, h("div", { class: "tabs", role: "tablist" }, tabLogin, tabReg), body),
    h("div", { class: "landing-points" },
      h("div", {}, h("b", {}, "Sıfır bilik"), "Seyf brauzerinizdə şifrələnir. Biz onun içini görə bilmirik."),
      h("div", {}, h("b", {}, "Heç kim təkbaşına"), "Açar etibarlı şəxslər arasında bölünür — biri kifayət etmir."),
      h("div", {}, h("b", {}, "Yalnız vaxtı çatanda"), "Uzun müddət cavab verməsəniz və gözləmə bitərsə açılır."))));
}

function loginForm(go) {
  const email = h("input", { type: "email", autocomplete: "username", required: true, id: "login-email" });
  const pw = h("input", { type: "password", autocomplete: "current-password", required: true, id: "login-password" });
  const totp = h("input", { type: "text", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", id: "login-totp" });
  const totpField = field("Autentifikator kodu", totp);
  totpField.classList.add("hidden");
  const btn = h("button", { type: "submit", class: "brass", id: "login-submit" }, "Daxil ol");
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    await busy(btn, async () => {
      try {
        await Sess.login({ email: email.value.trim().toLowerCase(), password: pw.value, totp: totp.value || undefined });
        pw.value = "";
        go(Sess.S.user.role === "auditor" ? "#/audit" : "#/vault");
      } catch (err) {
        if (err.code === "mfa_required") { totpField.classList.remove("hidden"); totp.focus(); toast("Autentifikator kodunu daxil edin"); }
        else toast(errText(err), "err");
      }
    });
  } }, field("E-poçt", email), field("Parol", pw, "Parolunuz serverə göndərilmir — ondan brauzerdə açar törədilir."),
  totpField, h("div", { class: "row" }, btn, h("a", { href: "#/recover", class: "small" }, "Parolu unutmusunuz?")));
  return form;
}

function registerForm(go) {
  const name = h("input", { type: "text", autocomplete: "name", required: true, id: "reg-name" });
  const email = h("input", { type: "email", autocomplete: "username", required: true, id: "reg-email" });
  const pw = h("input", { type: "password", autocomplete: "new-password", required: true, id: "reg-password" });
  const pw2 = h("input", { type: "password", autocomplete: "new-password", required: true, id: "reg-password2" });
  const ack = h("input", { type: "checkbox", id: "reg-ack" });
  const btn = h("button", { type: "submit", class: "brass", id: "reg-submit" }, "Hesab yarat");
  return h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    const em = email.value.trim().toLowerCase();
    const probs = passwordProblems(pw.value, em);
    if (probs.length) return toast("Parol: " + probs.join(", "), "err");
    if (pw.value !== pw2.value) return toast("Parollar uyğun gəlmir", "err");
    if (!ack.checked) return toast("Xəbərdarlığı təsdiqləyin", "err");
    await busy(btn, async () => {
      try {
        const { recoveryCode, rk } = await Sess.register({ email: em, name: name.value.trim(), password: pw.value });
        await Sess.login({ email: em, password: pw.value });
        await Sess.createVault(rk);
        rk.encKey.fill(0);
        pw.value = pw2.value = "";
        showRecovery(document.getElementById("root"), recoveryCode, () => go("#/vault"));
      } catch (err) { toast(errText(err), "err"); }
    });
  } },
  field("Adınız", name, "Etibarlı şəxslər sizi bu adla görəcək."), field("E-poçt", email),
  field("Master parol", pw, "Ən azı 12 simvol. Uzun ifadə yaxşıdır: “Xəzərin sahili 2026-cı ilin yazında”."),
  field("Parolu təkrarlayın", pw2),
  h("label", { class: "check" }, ack,
    h("span", {}, "Başa düşürəm: parolu və bərpa kodunu itirsəm, Əmanət də seyfimi aça bilməyəcək.")),
  btn);
}

export function showRecovery(root, code, done) {
  const ok = h("input", { type: "checkbox", id: "rc-ack" });
  const cont = h("button", { class: "brass", id: "rc-continue", disabled: true }, "Davam et");
  ok.onchange = () => { cont.disabled = !ok.checked; };
  cont.onclick = done;
  const dl = h("button", { class: "secondary", onclick: () => {
    const blob = new Blob([`Əmanət bərpa kodu\n\n${code}\n\nBu kodu çap edib təhlükəsiz yerdə saxlayın.\n`], { type: "text/plain" });
    const a = h("a", { href: URL.createObjectURL(blob), download: "emanet-berpa-kodu.txt" });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } }, "Fayl kimi yüklə");
  mount(root, h("div", { class: "auth" }, h("div", { class: "card stack" },
    h("h2", {}, "Bərpa kodunuz"),
    h("p", {}, "Parolu unutsanız, hesabınızı yalnız bu kodla bərpa edə bilərsiniz. Biz onu saxlamırıq və bir daha göstərməyəcəyik."),
    h("div", { class: "recovery", id: "recovery-code" }, code),
    h("div", { class: "row" }, dl, h("button", { class: "secondary", onclick: () => print() }, "Çap et")),
    h("label", { class: "check" }, ok, h("span", {}, "Kodu kağıza yazdım və ya təhlükəsiz yerdə saxladım.")),
    cont)));
}

export function lockScreen(root, go) {
  const pw = h("input", { type: "password", autocomplete: "current-password", id: "unlock-password" });
  const btn = h("button", { class: "brass", type: "submit", id: "unlock-submit" }, "Kilidi aç");
  mount(root, h("div", { class: "auth" }, h("div", { class: "lead" }, seal("seal"), h("h2", {}, "Seyf kilidlənib"),
    h("p", { class: "muted" }, `${Sess.S.user.display_name}, açarlarınız yalnız yaddaşda saxlanılır — səhifə yeniləndiyi üçün parolu yenidən daxil edin.`)),
  h("form", { class: "card stack", onsubmit: async (e) => {
    e.preventDefault();
    await busy(btn, async () => {
      try { await Sess.unlock(pw.value); pw.value = ""; go(location.hash || "#/vault"); }
      catch { toast("Parol yanlışdır", "err"); }
    });
  } }, field("Master parol", pw), h("div", { class: "row" }, btn,
    h("button", { type: "button", class: "ghost", onclick: async () => { await Sess.logout(); go("#/"); } }, "Başqa hesab")))));
}

export function recoverView(root, go) {
  const email = h("input", { type: "email", id: "rec-email" });
  const code = h("input", { type: "text", id: "rec-code", placeholder: "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", class: "mono" });
  const pw = h("input", { type: "password", autocomplete: "new-password", id: "rec-password" });
  const btn = h("button", { class: "brass", type: "submit" }, "Hesabı bərpa et");
  mount(root, h("div", { class: "auth" }, h("div", { class: "lead" }, h("h2", {}, "Bərpa kodu ilə giriş")),
    h("form", { class: "card stack", onsubmit: async (e) => {
      e.preventDefault();
      const probs = passwordProblems(pw.value, email.value);
      if (probs.length) return toast("Parol: " + probs.join(", "), "err");
      await busy(btn, async () => {
        try {
          const { newCode } = await Sess.recover({ email: email.value.trim().toLowerCase(), code: code.value, newPassword: pw.value });
          toast("Hesab bərpa olundu. Yeni bərpa kodunuzu saxlayın!");
          showRecovery(root, newCode, () => go("#/"));
        } catch (err) { toast(errText(err), "err"); }
      });
    } }, field("E-poçt", email), field("Bərpa kodu", code), field("Yeni master parol", pw), btn,
    h("a", { href: "#/", class: "small" }, "← Geri"))));
}
