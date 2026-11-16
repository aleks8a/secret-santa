
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

//showRegister.hidden = true;

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

// Password dimenticata: avvisa l'amministratore, che crea una password temporanea
document.getElementById("forgotPassword").addEventListener("click", async event => {
  const button = event.currentTarget;
  const loginName = document.getElementById("loginName").value.trim();

  if (!loginName) {
    message.textContent =
      "Scrivi il tuo nome utente nel campo qui sopra, poi premi di nuovo \"Ho dimenticato la password\".";
    document.getElementById("loginName").focus();
    return;
  }

  if (!confirm("Avvisare l'amministratore che hai dimenticato la password di \"" + loginName + "\"?")) {
    return;
  }

  try {
    button.disabled = true;
    message.textContent = "Invio della richiesta...";
    const result = await apiCall("request_password_reset", { login_name: loginName });
    message.textContent = result.message;
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
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

// Dopo l'accesso si va alla pagina personale
function showAccount() {
  window.location.href = "home.html";
}

// Cambio obbligatorio della password temporanea

function showPasswordChange(token, loginName) {
  loginForm.hidden = true;

  const resetForm = document.createElement("form");
  resetForm.id = "passwordChangeForm";

  resetForm.innerHTML = `
    <h2>Crea la tua nuova password</h2>
    <p>Scegli una password personale di almeno 6 caratteri.</p>
    <label for="newPassword">Nuova password</label>
    <input
      id="newPassword"
      type="password"
      minlength="6"
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

      // Verifica la nuova sessione
      await apiCall("whoami", {}, newToken);

      resetForm.remove();
      showAccount();

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

    await apiCall("whoami", {}, token);
    showAccount();

  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});


// Registrazione reale tramite Supabase Edge Function

form.addEventListener("submit", async event => {
  event.preventDefault();

  message.textContent = "Il modulo funziona: sto preparando la registrazione...";

  const parentName = document.getElementById("name").value.trim();
  const password = document.getElementById("password").value;

  if (!parentName || password.length < 6) {
    message.textContent =
      "Inserisci il nome e una password di almeno 6 caratteri.";
    return;
  }

  const childNames = hasChildren.checked
    ? children.map(name => name.trim())
    : [];

  if (childNames.some(name => !name)) {
    message.textContent =
      "Completa tutti i nomi dei figli oppure rimuovi i campi vuoti.";
    return;
  }

  const button = form.querySelector('button[type="submit"]');

  try {
    button.disabled = true;
    message.textContent = "Registrazione in corso...";

    const result = await apiCall("register", {
      name: parentName,
      password,
      children: childNames
    });

    registerSection.hidden = true;
    loginSection.hidden = false;
    showRegister.hidden = false;

    form.reset();
    children = [];
    renderChildren();
    childrenArea.hidden = true;

    document.getElementById("loginName").value = parentName;
    document.getElementById("loginPassword").value = "";

    message.textContent =
      result.message + " Puoi accedere con il nome utente " +
      result.account.login_name + ".";

  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});


// Se la sessione è ancora valida, niente login: si apre la pagina personale
(async function resumeSession() {
  const token = sessionStorage.getItem("ss_access_token");
  if (!token) return;

  try {
    await apiCall("whoami", {}, token);
    window.location.replace("home.html");
  } catch {
    sessionStorage.removeItem("ss_access_token");
  }
})();
