// Funzioni condivise dalle pagine dopo l'accesso
const SS_SUPABASE_URL = "https://peyedqobyytqwnxaovcr.supabase.co";
const SS_ANON_KEY = "sb_publishable_u821cPWqBYZMRlqH0gaSbg_NSooa7_5";
const SS_FUNCTION_URL = SS_SUPABASE_URL + "/functions/v1/secret-santa";
const SS_TOKEN_KEY = "ss_access_token";

function ssToken() {
  return sessionStorage.getItem(SS_TOKEN_KEY);
}

async function ssApi(action, data = {}) {
  const token = ssToken();
  const headers = {
    "Content-Type": "application/json",
    "apikey": SS_ANON_KEY
  };
  if (token) headers.Authorization = "Bearer " + token;

  const response = await fetch(SS_FUNCTION_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ action, ...data })
  });

  let result = {};
  try { result = await response.json(); } catch { /* risposta non JSON */ }

  if (!response.ok) {
    const error = new Error(result.error || "Si è verificato un errore.");
    error.status = response.status;
    error.data = result;
    throw error;
  }
  return result;
}

// Esce dall'account e torna alla pagina di accesso
function ssLogout() {
  sessionStorage.removeItem(SS_TOKEN_KEY);
  window.location.href = "index.html";
}

// Sessione scaduta o non valida: pulisce e rimanda all'accesso
function ssSessionExpired(error) {
  return error && (error.status === 401 || error.status === 404);
}
