
const form = document.getElementById("registrationForm");
const hasChildren = document.getElementById("hasChildren");
const childrenArea = document.getElementById("childrenArea");
const childrenList = document.getElementById("childrenList");
const wishlists = document.getElementById("wishlists");
const message = document.getElementById("message");

let children = [];
let wishlistData = {
  parent: []
};

function createWishlist(personId, personName) {
  const card = document.createElement("section");
  card.className = "wishlist-card";

  const title = document.createElement("h3");
  title.textContent = "🎁 Regali desiderati – " + personName;
  card.appendChild(title);

  const giftInput = document.createElement("input");
  giftInput.type = "text";
  giftInput.placeholder = "Nome del regalo";
  giftInput.maxLength = 200;
  giftInput.setAttribute("aria-label", "Nome del regalo");
  card.appendChild(giftInput);

  const urlInput = document.createElement("input");
  urlInput.type = "url";
  urlInput.placeholder = "Link Amazon (facoltativo)";
  urlInput.style.marginTop = "10px";
  card.appendChild(urlInput);

  const addButton = document.createElement("button");
  addButton.type = "button";
  addButton.className = "secondary";
  addButton.textContent = "+ Aggiungi regalo";
  card.appendChild(addButton);

  const list = document.createElement("div");
  card.appendChild(list);

  addButton.addEventListener("click", () => {
    const name = giftInput.value.trim();
    const url = urlInput.value.trim();

    if (!name) {
      message.textContent = "Inserisci il nome del regalo.";
      return;
    }

    if (url) {
      try {
        const parsed = new URL(url);

        if (
          parsed.protocol !== "https:" ||
          !["amazon.it", "www.amazon.it"].includes(parsed.hostname)
        ) {
          throw new Error("Link non valido");
        }
      } catch {
        message.textContent = "Inserisci un link Amazon.it valido.";
        return;
      }
    }

    wishlistData[personId].push({ name, url });
    giftInput.value = "";
    urlInput.value = "";
    renderWishlist(personId, list);
    message.textContent = "";
  });

  return card;
}

function renderWishlist(personId, list) {
  list.replaceChildren();

  wishlistData[personId].forEach((gift, index) => {
    const row = document.createElement("div");
    row.className = "gift-row";

    const name = document.createElement("span");
    name.textContent = gift.name;
    row.appendChild(name);

    if (gift.url) {
      const link = document.createElement("a");
      link.href = gift.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Apri";
      row.appendChild(link);
    }

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove";
    remove.textContent = "×";
    remove.setAttribute("aria-label", "Rimuovi regalo");

    remove.addEventListener("click", () => {
      wishlistData[personId].splice(index, 1);
      renderWishlist(personId, list);
    });

    row.appendChild(remove);
    list.appendChild(row);
  });
}

function updateWishlists() {
  wishlists.replaceChildren();

  const parentName =
    document.getElementById("name").value.trim() || "Genitore";

  const parentCard = createWishlist("parent", parentName);
  wishlists.appendChild(parentCard);

  children.forEach((child, index) => {
    const id = "child-" + index;
    const name = child.trim() || "Figlio/a " + (index + 1);

    if (!wishlistData[id]) {
      wishlistData[id] = [];
    }

    wishlists.appendChild(createWishlist(id, name));
  });
}

function renderChildren() {
  childrenList.replaceChildren();

  children.forEach((name, index) => {
    const card = document.createElement("div");
    card.className = "child-card";

    const label = document.createElement("label");
    label.textContent = "Nome e cognome del figlio/a " + (index + 1);
    card.appendChild(label);

    const input = document.createElement("input");
    input.type = "text";
    input.required = true;
    input.maxLength = 60;
    input.value = name;
    input.placeholder = "Es. Sofia Rossi";

    input.addEventListener("input", () => {
      children[index] = input.value;
      updateWishlists();
    });

    card.appendChild(input);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove";
    remove.textContent = "Rimuovi figlio/a";

    remove.addEventListener("click", () => {
      const oldId = "child-" + index;
      delete wishlistData[oldId];

      children.splice(index, 1);

      const previous = { ...wishlistData };
      wishlistData = { parent: [], ...previous };

      children.forEach((child, i) => {
        if (!wishlistData["child-" + i]) {
          wishlistData["child-" + i] = [];
        }
      });

      renderChildren();
      updateWishlists();
    });

    card.appendChild(remove);
    childrenList.appendChild(card);
  });

  updateWishlists();
}

hasChildren.addEventListener("change", () => {
  childrenArea.hidden = !hasChildren.checked;

  if (!hasChildren.checked) {
    children = [];
    Object.keys(wishlistData).forEach(key => {
      if (key !== "parent") delete wishlistData[key];
    });
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

document.getElementById("name").addEventListener("input", () => {
  updateWishlists();
});

form.addEventListener("submit", event => {
  event.preventDefault();

  const parentName = document.getElementById("name").value.trim();
  const password = document.getElementById("password").value;

  if (!parentName || password.length < 10) {
    message.textContent =
      "Inserisci il nome e una password di almeno 10 caratteri.";
    return;
  }

  if (hasChildren.checked) {
    if (
      children.length === 0 ||
      children.some(name => !name.trim())
    ) {
      message.textContent =
        "Inserisci il nome di tutti i figli oppure rimuovi i campi vuoti.";
      return;
    }
  }

  message.textContent =
    "La pagina di prova funziona! La registrazione online non è ancora attiva. Non chiudere questa pagina se vuoi conservare temporaneamente i dati inseriti.";
});

updateWishlists();
