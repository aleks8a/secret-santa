
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
function showPasswordChange(token) {
  loginForm.hidden = true;

  const resetForm = document.createElement("form");
  resetForm.id = "passwordResetForm";

  const title = document.createElement("h2");
  title.textContent = "Crea una nuova password";
  resetForm.appendChild(title);

  const description = document.createElement("p");
  description.textContent =
    "Per continuare devi sostituire la password temporanea.";
  resetForm.appendChild(description);

  const label = document.createElement("label");
  label.textContent = "Nuova password";
  label.htmlFor = "newPassword";
  resetForm.appendChild(label);

  const input = document.createElement("input");
  input.id = "newPassword";
  input.type = "password";
  input.minLength = 12;
  input.maxLength = 128;
  input.autocomplete = "new-password";
  input.required = true;
  resetForm.appendChild(input);

  const button = document.createElement("button");
  button.type = "submit";
  button.className = "primary";
  button.textContent = "Cambia password";
  resetForm.appendChild(button);

  loginSection.appendChild(resetForm);

  resetForm.addEventListener("submit", async event => {
    event.preventDefault();

    try {
      button.disabled = true;
      message.textContent = "Aggiornamento password in corso...";

      await apiCall(
        "change_password",
        { new_password: input.value },
        token
      );

      const accountData = await apiCall("whoami", {}, token);

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
      showPasswordChange(token);
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
