
const SUPABASE_URL = "https://peyedqobyytqwnxaovcr.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_u821cPWqBYZMRlqH0gaSbg_NSooa7_5";
const FUNCTION_URL = SUPABASE_URL + "/functions/v1/secret-santa";

const form = document.getElementById("registrationForm");
const loginForm = document.getElementById("loginForm");

const hasChildren = document.getElementById("hasChildren");
const childrenArea = document.getElementById("childrenArea");
const childrenList = document.getElementById("childrenList");
const message = document.getElementById("message");

const loginSection = document.getElementById("loginSection");
const registerSection = document.getElementById("registerSection");
const showLogin = document.getElementById("showLogin");
const showRegister = document.getElementById("showRegister");

showRegister.hidden = true;
let children = [];

async function apiCall(action, data = {}, token = null) {
  const headers = {
    "Content-Type": "application/json",
    "apikey": SUPABASE_ANON_KEY
  };

  if (token) {
    headers.Authorization = "Bearer " + token;
  }

  const response = await fetch(FUNCTION_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ action, ...data })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(result.error || "Si è verificato un errore.");
  }

  return result;
}

// Passaggio tra accesso e registrazione
showLogin.addEventListener("click", () => {
  loginSection.hidden = false;
  registerSection.hidden = true;
  message.textContent = "";
});

showRegister.addEventListener("click", () => {
  loginSection.hidden = true;
  registerSection.hidden = false;
  message.textContent = "";
});

// Gestione dei figli
function renderChildren() {
  childrenList.replaceChildren();

  children.forEach((name, index) => {
    const card = document.createElement("div");
    card.className = "child-card";

    const label = document.createElement("label");
    label.textContent =
      "Nome e cognome del figlio/a " + (index + 1);
    card.appendChild(label);

    const input = document.createElement("input");
    input.type = "text";
    input.required = true;
    input.maxLength = 60;
    input.value = name;
    input.placeholder = "Es. Sofia Rossi";

    input.addEventListener("input", () => {
      children[index] = input.value;
    });

    card.appendChild(input);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove";
    remove.textContent = "Rimuovi figlio/a";

    remove.addEventListener("click", () => {
      children.splice(index, 1);
      renderChildren();
    });

    card.appendChild(remove);
    childrenList.appendChild(card);
  });
}

hasChildren.addEventListener("change", () => {
  childrenArea.hidden = !hasChildren.checked;

  if (!hasChildren.checked) {
    children = [];
    renderChildren();
  } else if (children.length === 0) {
    children.push("");
    renderChildren();
  }
});

document.getElementById("addChild").addEventListener("click", () => {
  children.push("");
  renderChildren();
});

// Mostra il risultato del login e i partecipanti dell'account
function showAccount(data) {
  showRegister.hidden = true;
  loginSection.hidden = true;
  registerSection.hidden = true;
  loginForm.hidden = true;

  message.textContent =
    "Accesso effettuato! Benvenuto, " +
    data.account.login_name + ".";

  const details = document.createElement("p");
  details.textContent =
    "Partecipanti associati a questo account: " +
    data.participants.map(p => p.display_name).join(", ");

  message.appendChild(document.createElement("br"));
  message.appendChild(details);

  const wishlistLink = document.createElement("a");
  wishlistLink.href = "wishlist.html";
  wishlistLink.textContent = "La mia wishlist";

  const santaLink = document.createElement("a");
  santaLink.href = "secret-santa.html";
  santaLink.textContent = "Il nostro Secret Santa";

  message.appendChild(wishlistLink);
  message.appendChild(document.createElement("br"));
  message.appendChild(santaLink);
}

// Cambio obbligatorio della password temporanea

function showPasswordChange(token, loginName) {
  loginForm.hidden = true;

  const resetForm = document.createElement("form");
  resetForm.id = "passwordChangeForm";

  resetForm.innerHTML = `
    <h2>Crea la tua nuova password</h2>
    <p>Scegli una password personale di almeno 12 caratteri.</p>
    <label for="newPassword">Nuova password</label>
    <input
      id="newPassword"
      type="password"
      minlength="12"
      maxlength="128"
      autocomplete="new-password"
      required
    >
    <button type="submit" class="primary">Salva password</button>
  `;

  loginSection.appendChild(resetForm);

  resetForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const button = resetForm.querySelector("button");
    const newPassword = document.getElementById("newPassword").value;

    button.disabled = true;
    message.textContent = "Aggiornamento password in corso...";

    try {
      await apiCall("change_password", {
        new_password: newPassword
      }, token);

      // Effettua un nuovo login con la password appena impostata
      const loginResult = await apiCall("login", {
        login_name: loginName,
        password: newPassword
      });

      const newToken = loginResult.session.access_token;
      sessionStorage.setItem("ss_access_token", newToken);

      // Recupera i dati dell'account con la nuova sessione
      const accountData = await apiCall("whoami", {}, newToken);

      resetForm.remove();
      showAccount(accountData);

    } catch (error) {
      message.textContent = error.message;
      button.disabled = false;
    }
  });
}

// Login reale tramite Supabase Edge Function
loginForm.addEventListener("submit", async event => {
  event.preventDefault();

  const loginName = document.getElementById("loginName").value.trim();
  const password = document.getElementById("loginPassword").value;
  const button = loginForm.querySelector('button[type="submit"]');

  try {
    button.disabled = true;
    message.textContent = "Accesso in corso...";

    const result = await apiCall("login", {
      login_name: loginName,
      password
    });

    const token = result.session.access_token;

    sessionStorage.setItem("ss_access_token", token);

    if (result.must_reset_password) {
      message.textContent = "";
      showPasswordChange(token, result.account.login_name);
      return;
    }

    const accountData = await apiCall("whoami", {}, token);
    showAccount(accountData);

  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

// Registrazione: il backend non è ancora pronto
form.addEventListener("submit", event => {
  event.preventDefault();

  const parentName = document.getElementById("name").value.trim();
  const password = document.getElementById("password").value;

  if (!parentName || password.length < 12) {
    message.textContent =
      "Inserisci il nome e una password di almeno 12 caratteri.";
    return;
  }

  if (
    hasChildren.checked &&
    (
      children.length === 0 ||
      children.some(name => !name.trim())
    )
  ) {
    message.textContent =
      "Inserisci il nome di tutti i figli oppure rimuovi i campi vuoti.";
    return;
  }

  message.textContent =
    "La registrazione online sarà attivata nel prossimo passaggio.";
});
