
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

// Attivazione o disattivazione della gestione famiglia
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

// Aggiunta di un figlio
document.getElementById("addChild").addEventListener("click", () => {
  children.push("");
  renderChildren();
});

// Invio registrazione
form.addEventListener("submit", event => {
  event.preventDefault();

  const parentName =
    document.getElementById("name").value.trim();

  const password =
    document.getElementById("password").value;

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
    "La registrazione online non è ancora attiva. I dati inseriti non vengono ancora salvati.";
});

// Invio login
loginForm.addEventListener("submit", event => {
  event.preventDefault();

  message.textContent =
    "L'accesso online non è ancora collegato. Lo attiveremo nel prossimo passaggio.";
});
