// Countdown nella parte alta dell'intestazione (non cambia l'altezza del pannello).
// Prima dell'estrazione conta fino alla data dell'estrazione; dopo l'estrazione
// conta fino al 25 dicembre ore 00:00. Allo scadere sparisce.
(function () {
  const hero = document.querySelector(".hero");
  if (!hero) return;

  const URL = "https://peyedqobyytqwnxaovcr.supabase.co/functions/v1/secret-santa";
  const KEY = "sb_publishable_u821cPWqBYZMRlqH0gaSbg_NSooa7_5";

  const box = document.createElement("div");
  box.className = "countdown";
  box.hidden = true;
  hero.appendChild(box);

  let target = 0;
  let label = "";
  let timer = null;

  const pad = n => String(n).padStart(2, "0");

  function tick() {
    const ms = target - Date.now();
    if (ms <= 0) {
      box.hidden = true;
      clearInterval(timer);
      return;
    }
    const total = Math.floor(ms / 1000);
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    box.textContent = label + " " + (days > 0 ? days + "g " : "") +
      pad(hours) + ":" + pad(minutes) + ":" + pad(seconds);
    box.hidden = false;
  }

  fetch(URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "apikey": KEY },
    body: JSON.stringify({ action: "public_info" })
  })
    .then(r => r.ok ? r.json() : null)
    .then(info => {
      if (!info) return;
      if (info.draw_done) {
        target = Date.parse(info.reveal_at);
        label = "🎁 Rivelazione tra";
      } else if (info.draw_date) {
        target = Date.parse(info.draw_date);
        label = "⏳ Estrazione tra";
      }
      if (!target || target <= Date.now()) return;
      tick();
      timer = setInterval(tick, 1000);
    })
    .catch(() => { /* il countdown è facoltativo */ });
})();
