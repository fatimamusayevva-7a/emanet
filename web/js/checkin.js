// E-poçtdakı birdəfəlik "sağam" linki. Token URL fraqmentindədir (#t=…):
// brauzer fraqmenti serverə və Referer başlığına göndərmir.
import { post } from "./api.js";

const token = new URLSearchParams(location.hash.slice(1)).get("t");
history.replaceState(null, "", location.pathname);   // token ünvan sətrindən və tarixçədən silinir
const btn = document.getElementById("confirm");
const out = document.getElementById("result");
if (!token) { btn.disabled = true; out.textContent = "Link natamamdır."; }
btn.addEventListener("click", async () => {
  btn.disabled = true;
  try {
    await post("/api/checkin-link", { token });
    out.textContent = "Təşəkkür edirik! Sayğac sıfırlandı. Bu səhifəni bağlaya bilərsiniz.";
  } catch (e) {
    out.textContent = e.message || "Link etibarsızdır.";
  }
});
