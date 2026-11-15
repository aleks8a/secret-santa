
import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get(
  "SUPABASE_SERVICE_ROLE_KEY",
)!;

const adminClient = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  },
);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function validText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
// CIFRATURA DELLE WISHLIST
async function getWishlistEncryptionKey() {
  const secret = Deno.env.get("WISHLIST_ENCRYPTION_KEY");

  if (!secret || secret.length < 40) {
    throw new Error("Chiave di cifratura non configurata");
  }

  const keyMaterial = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(secret),
  );

  return await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value: string) {
  return Uint8Array.from(
    atob(value),
    character => character.charCodeAt(0),
  );
}

async function encryptWishlist(gifts: unknown[]) {
  const key = await getWishlistEncryptionKey();
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const plaintext = new TextEncoder().encode(
    JSON.stringify(gifts),
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    plaintext,
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    nonce: bytesToBase64(nonce),
    key_version: 1,
  };
}

async function decryptWishlist(
  ciphertext: string,
  nonce: string,
) {
  const key = await getWishlistEncryptionKey();

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(nonce),
    },
    key,
    base64ToBytes(ciphertext),
  );

  return JSON.parse(
    new TextDecoder().decode(decrypted),
  );
}

// FUNZIONI DI SUPPORTO PER ADMIN, ESTRAZIONE E SELEZIONE DEI REGALI
const TEMP_PASSWORD_ALPHABET =
  "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// Password temporanea leggibile al telefono (niente 0/O, 1/l/I)
function generateTempPassword(length = 10) {
  let result = "";

  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));

    for (const byte of bytes) {
      // scarta i valori che introdurrebbero una distorsione statistica
      if (byte < 216 && result.length < length) {
        result += TEMP_PASSWORD_ALPHABET[
          byte % TEMP_PASSWORD_ALPHABET.length
        ];
      }
    }
  }

  return result;
}

// Identificatore stabile di un regalo: cambia solo se il proprietario
// modifica nome o link (in quel caso la vecchia selezione decade).
async function giftKey(
  participantId: string,
  gift: { name: string; url?: string },
) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      `${participantId}|${gift.name}|${gift.url ?? ""}`,
    ),
  );

  return Array.from(
    new Uint8Array(hash).slice(0, 16),
    byte => byte.toString(16).padStart(2, "0"),
  ).join("");
}

type KeyedGift = { name: string; url?: string; gift_key: string };

// Carica e decifra le wishlist di più partecipanti
async function loadGifts(participantIds: string[]) {
  const result = new Map<string, KeyedGift[]>();

  if (participantIds.length === 0) return result;

  const { data: wishlists, error } = await adminClient
    .from("ss_wishlists")
    .select("participant_id, ciphertext, nonce")
    .in("participant_id", participantIds);

  if (error) throw new Error("Errore nel recupero delle wishlist");

  await Promise.all((wishlists ?? []).map(async saved => {
    const gifts = await decryptWishlist(saved.ciphertext, saved.nonce);
    const keyed: KeyedGift[] = [];

    for (const gift of gifts as { name: string; url?: string }[]) {
      keyed.push({
        name: gift.name,
        ...(gift.url ? { url: gift.url } : {}),
        gift_key: await giftKey(saved.participant_id, gift),
      });
    }

    result.set(saved.participant_id, keyed);
  }));

  return result;
}

// Estrazione: la tabella ss_assignments è cifrata (participant_id, ciphertext, nonce).
// Ogni riga appartiene a chi FA il regalo e contiene l'id di chi lo RICEVE.
// Restituisce una mappa chi-fa-il-regalo -> chi-lo-riceve per l'edizione.
async function loadAssignmentMap(editionId: string) {
  const map = new Map<string, string>();

  const { data: people, error: peopleError } = await adminClient
    .from("ss_participants")
    .select("id")
    .eq("edition_id", editionId);

  if (peopleError) throw new Error("Errore nel recupero partecipanti");

  const ids = (people ?? []).map(item => item.id);
  if (ids.length === 0) return map;

  const { data: rows, error: rowsError } = await adminClient
    .from("ss_assignments")
    .select("participant_id, ciphertext, nonce")
    .in("participant_id", ids);

  if (rowsError) {
    console.error("ss_assignments lookup:", rowsError.message);
    throw new Error("Errore nel recupero delle assegnazioni");
  }

  await Promise.all((rows ?? []).map(async row => {
    const plain = await decryptWishlist(row.ciphertext, row.nonce);
    const receiverId = plain?.[0]?.receiver_participant_id;
    if (receiverId) map.set(row.participant_id, receiverId);
  }));

  return map;
}

// A chi devono fare il regalo i partecipanti di un account
async function loadMyAssignments(
  accountId: string,
  editionId: string,
) {
  const { data: mine, error: mineError } = await adminClient
    .from("ss_participants")
    .select("id, display_name")
    .eq("account_id", accountId)
    .eq("edition_id", editionId)
    .order("display_name");

  if (mineError) throw new Error("Errore nel recupero partecipanti");

  const myIds = (mine ?? []).map(item => item.id);

  const assignmentMap = await loadAssignmentMap(editionId);
  const assignments = myIds
    .filter(id => assignmentMap.has(id))
    .map(id => ({
      giver_participant_id: id,
      receiver_participant_id: assignmentMap.get(id)!,
    }));

  const receiverIds = (assignments ?? []).map(
    item => item.receiver_participant_id,
  );

  const { data: receivers, error: receiversError } = receiverIds.length
    ? await adminClient
        .from("ss_participants")
        .select("id, display_name")
        .in("id", receiverIds)
    : { data: [], error: null };

  if (receiversError) throw new Error("Errore nel recupero delle assegnazioni");

  const receiverById = new Map(
    (receivers ?? []).map(item => [item.id, item.display_name]),
  );
  const assignmentByGiver = new Map(
    (assignments ?? []).map(item => [
      item.giver_participant_id,
      item.receiver_participant_id,
    ]),
  );

  return (mine ?? []).map(participant => {
    const receiverId = assignmentByGiver.get(participant.id) ?? null;

    return {
      giver_participant_id: participant.id,
      giver_name: participant.display_name,
      receiver_participant_id: receiverId,
      receiver_name: receiverId ? receiverById.get(receiverId) ?? null : null,
    };
  });
}

// Crea un account con i relativi partecipanti (usato dall'amministratore)
async function createFamilyAccount(options: {
  editionId: string;
  adultName: string;
  childNames: string[];
  password: string;
  mustResetPassword: boolean;
}) {
  const { editionId, adultName, childNames, password, mustResetPassword } =
    options;

  const allNames = [adultName, ...childNames];
  const normalized = allNames.map(name => name.toLocaleLowerCase("it"));

  if (new Set(normalized).size !== normalized.length) {
    return {
      error: "Non puoi inserire due partecipanti con lo stesso nome.",
      status: 400,
    };
  }

  const { data: existingAccounts, error: accountsError } =
    await adminClient
      .from("ss_accounts")
      .select("login_name")
      .eq("edition_id", editionId);

  const { data: existingParticipants, error: participantsError } =
    await adminClient
      .from("ss_participants")
      .select("display_name")
      .eq("edition_id", editionId);

  if (accountsError || participantsError) {
    return {
      error: "Impossibile verificare i nomi già registrati.",
      status: 500,
    };
  }

  const existingNames = new Set([
    ...(existingAccounts ?? []).map(
      item => item.login_name.toLocaleLowerCase("it"),
    ),
    ...(existingParticipants ?? []).map(
      item => item.display_name.toLocaleLowerCase("it"),
    ),
  ]);

  const duplicateName = allNames.find(
    name => existingNames.has(name.toLocaleLowerCase("it")),
  );

  if (duplicateName) {
    return {
      error: `Il nome "${duplicateName}" è già utilizzato. Scegli un nome diverso.`,
      status: 409,
    };
  }

  const authResult = await adminClient.auth.admin.createUser({
    email: `ss-${crypto.randomUUID()}@example.com`,
    password,
    email_confirm: true,
  });

  if (authResult.error || !authResult.data?.user) {
    console.error("Admin create user (auth):", authResult.error?.message);
    return {
      error: "Non è stato possibile creare l'account.",
      status: 500,
    };
  }

  const authUserId = authResult.data.user.id;
  const accountId = crypto.randomUUID();
  const now = new Date().toISOString();

  const { error: newAccountError } = await adminClient
    .from("ss_accounts")
    .insert({
      id: accountId,
      edition_id: editionId,
      login_name: adultName,
      auth_user_id: authUserId,
      role: "user",
      must_reset_password: mustResetPassword,
      created_at: now,
    });

  if (newAccountError) {
    console.error("Admin create user (account):", newAccountError.message);
    await adminClient.auth.admin.deleteUser(authUserId);
    return {
      error: "Non è stato possibile creare l'account.",
      status: 409,
    };
  }

  const newParticipants = allNames.map((displayName, index) => ({
    id: crypto.randomUUID(),
    edition_id: editionId,
    account_id: accountId,
    display_name: displayName,
    participant_type: index === 0 ? "adult" : "minor",
    must_reset_password: mustResetPassword,
    created_at: now,
  }));

  const { error: newParticipantsError } = await adminClient
    .from("ss_participants")
    .insert(newParticipants);

  if (newParticipantsError) {
    console.error(
      "Admin create user (participants):",
      newParticipantsError.message,
    );
    await adminClient.from("ss_accounts").delete().eq("id", accountId);
    await adminClient.auth.admin.deleteUser(authUserId);
    return {
      error: "Non è stato possibile registrare tutti i partecipanti.",
      status: 409,
    };
  }

  return { accountId, participants: newParticipants };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return response({ error: "Metodo non consentito" }, 405);
  }

  try {
    const body = await req.json();
    const action = body.action;

    if (action === "health") {
      return response({
        success: true,
        service: "secret-santa",
      });
    }

    // REGISTRAZIONE DI UNA NUOVA FAMIGLIA
    if (action === "register") {
      const adultName = body.name;
      const password = body.password;
      const children = body.children ?? [];

      if (
        !validText(adultName) ||
        adultName.trim().length > 100 ||
        !validText(password) ||
        password.length < 6 ||
        password.length > 128 ||
        !Array.isArray(children) ||
        children.length > 10
      ) {
        return response({
          error: "Controlla nome, password e numero dei figli. La password deve avere almeno 6 caratteri.",
        }, 400);
      }

      const normalizedAdultName = adultName.trim();
      const childNames: string[] = [];

      for (const child of children) {
        if (
          !validText(child) ||
          child.trim().length > 100
        ) {
          return response({
            error: "Uno dei nomi dei figli non è valido.",
          }, 400);
        }

        childNames.push(child.trim());
      }

      const allNames = [
        normalizedAdultName,
        ...childNames,
      ];

      const normalizedNames = allNames.map(
        name => name.toLocaleLowerCase("it"),
      );

      if (new Set(normalizedNames).size !== normalizedNames.length) {
        return response({
          error: "Non puoi inserire due partecipanti con lo stesso nome.",
        }, 400);
      }

      // Recupera l'edizione attiva
      const { data: edition, error: editionError } =
        await adminClient
          .from("ss_editions")
          .select("id, status, registration_deadline")
          .eq("year", 2026)
          .maybeSingle();

      if (editionError || !edition) {
        return response({
          error: "Edizione non disponibile.",
        }, 500);
      }

      if (edition.status !== "registration") {
        return response({
          error: "Le iscrizioni non sono attualmente aperte.",
        }, 403);
      }

      if (
        edition.registration_deadline &&
        Date.now() > new Date(edition.registration_deadline).getTime()
      ) {
        return response({
          error: "Il termine per le iscrizioni è scaduto.",
        }, 403);
      }

      // Controlla i nomi già utilizzati nell'edizione
      const { data: existingAccounts, error: accountsError } =
        await adminClient
          .from("ss_accounts")
          .select("login_name")
          .eq("edition_id", edition.id);

      const { data: existingParticipants, error: participantsError } =
        await adminClient
          .from("ss_participants")
          .select("display_name")
          .eq("edition_id", edition.id);

      if (accountsError || participantsError) {
        return response({
          error: "Impossibile verificare i nomi già registrati.",
        }, 500);
      }

      const existingNames = new Set([
        ...(existingAccounts ?? []).map(
          item => item.login_name.toLocaleLowerCase("it"),
        ),
        ...(existingParticipants ?? []).map(
          item => item.display_name.toLocaleLowerCase("it"),
        ),
      ]);

      const duplicateName = allNames.find(
        name => existingNames.has(name.toLocaleLowerCase("it")),
      );

      if (duplicateName) {
        return response({
          error: `Il nome "${duplicateName}" è già utilizzato. Scegli un nome diverso.`,
        }, 409);
      }

      // Crea un'email tecnica casuale, mai mostrata agli utenti
      const authEmail =
        `ss-${crypto.randomUUID()}@example.com`;

      const authResult =
        await adminClient.auth.admin.createUser({
          email: authEmail,
          password,
          email_confirm: true,
        });

      if (authResult.error || !authResult.data?.user) {
        console.error(
          "Auth registration:",
          authResult.error?.message,
        );

        return response({
          error: "Non è stato possibile creare l'account.",
        }, 500);
      }

      const authUserId = authResult.data.user.id;
      const accountId = crypto.randomUUID();
      const now = new Date().toISOString();

      // Crea l'account familiare
      const { error: newAccountError } =
        await adminClient
          .from("ss_accounts")
          .insert({
            id: accountId,
            edition_id: edition.id,
            login_name: normalizedAdultName,
            auth_user_id: authUserId,
            role: "user",
            must_reset_password: false,
            created_at: now,
          });

      if (newAccountError) {
        console.error(
          "Account registration:",
          newAccountError.message,
        );

        await adminClient.auth.admin.deleteUser(authUserId);

        return response({
          error: "Non è stato possibile creare l'account. Verifica che il nome non sia già utilizzato.",
        }, 409);
      }

      // Crea il genitore e gli eventuali figli come partecipanti
      const newParticipants = allNames.map(
        (displayName, index) => ({
          id: crypto.randomUUID(),
          edition_id: edition.id,
          account_id: accountId,
          display_name: displayName,
          participant_type: index === 0 ? "adult" : "minor",
          must_reset_password: false,
          created_at: now,
        }),
      );

      const { error: newParticipantsError } =
        await adminClient
          .from("ss_participants")
          .insert(newParticipants);

      if (newParticipantsError) {
        console.error(
          "Participant registration:",
          newParticipantsError.message,
        );

        await adminClient
          .from("ss_accounts")
          .delete()
          .eq("id", accountId);

        await adminClient.auth.admin.deleteUser(authUserId);

        return response({
          error: "Non è stato possibile registrare tutti i partecipanti. Controlla che i nomi non siano già utilizzati.",
        }, 409);
      }

      return response({
        success: true,
        message: "Registrazione completata. Ora puoi accedere.",
        account: {
          login_name: normalizedAdultName,
        },
        participants: newParticipants.map(item => ({
          id: item.id,
          display_name: item.display_name,
        })),
      }, 201);
    }

    // LOGIN: nome utente + password
    if (action === "login") {
      const loginName = body.login_name;
      const password = body.password;

      if (
        !validText(loginName) ||
        !validText(password) ||
        loginName.length > 100 ||
        loginName.includes("%") ||
        loginName.includes("_")
      ) {
        return response({ error: "Credenziali non valide" }, 400);
      }

      const { data: account, error: accountError } =
        await adminClient
          .from("ss_accounts")
          .select("id, auth_user_id")
          .ilike("login_name", loginName.trim())
          .maybeSingle();

      if (
        accountError ||
        !account ||
        !account.auth_user_id
      ) {
        return response({ error: "Credenziali non valide" }, 401);
      }

      const { data: authUser, error: userError } =
        await adminClient.auth.admin.getUserById(
          account.auth_user_id,
        );

      if (userError || !authUser.user?.email) {
        return response({ error: "Credenziali non valide" }, 401);
      }

      const loginClient = createClient(
        SUPABASE_URL,
        SUPABASE_ANON_KEY,
        {
          auth: {
            persistSession: false,
            autoRefreshToken: false,
          },
        },
      );

      const { data: loginData, error: loginError } =
        await loginClient.auth.signInWithPassword({
          email: authUser.user.email,
          password,
        });

      if (
        loginError ||
        !loginData.user ||
        loginData.user.id !== account.auth_user_id ||
        !loginData.session
      ) {
        return response({ error: "Credenziali non valide" }, 401);
      }

      const { data: accountData, error: accountDataError } =
        await adminClient
          .from("ss_accounts")
          .select("id, login_name, role, must_reset_password")
          .eq("id", account.id)
          .single();

      if (accountDataError || !accountData) {
        return response({ error: "Errore nel recupero account" }, 500);
      }

      return response({
        success: true,
        session: loginData.session,
        account: accountData,
        must_reset_password: accountData.must_reset_password,
      });
    }

    // AUTENTICAZIONE PER LE AZIONI PROTETTE
    const authorization = req.headers.get("Authorization");

    if (!authorization?.startsWith("Bearer ")) {
      return response({ error: "Autenticazione richiesta" }, 401);
    }

    const token = authorization.slice(7);

    const authClient = createClient(
      SUPABASE_URL,
      SUPABASE_ANON_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      },
    );

    const {
      data: { user },
      error: authError,
    } = await authClient.auth.getUser(token);

    if (authError || !user) {
      return response({ error: "Sessione non valida" }, 401);
    }

    const { data: account, error: accountError } =
      await adminClient
        .from("ss_accounts")
        .select(
          "id, edition_id, login_name, role, must_reset_password",
        )
        .eq("auth_user_id", user.id)
        .maybeSingle();

    if (accountError || !account) {
      return response({ error: "Account non trovato" }, 404);
    }

    // CAMBIO PASSWORD
    if (action === "change_password") {
      const newPassword = body.new_password;

      if (
        !validText(newPassword) ||
        newPassword.length < 6 ||
        newPassword.length > 128
      ) {
        return response({
          error: "La nuova password deve avere almeno 6 caratteri",
        }, 400);
      }

      const { error: passwordError } =
        await adminClient.auth.admin.updateUserById(
          user.id,
          { password: newPassword },
        );

      if (passwordError) {
        console.error("Password update:", passwordError.message);
        return response({ error: "Errore nel cambio password" }, 500);
      }

      const { error: updateAccountError } =
        await adminClient
          .from("ss_accounts")
          .update({ must_reset_password: false })
          .eq("id", account.id);

      if (updateAccountError) {
        console.error("Account reset update:", updateAccountError.message);
        return response({
          error: "Password cambiata, ma aggiornamento account non completato",
        }, 500);
      }

      const { error: updateParticipantsError } =
        await adminClient
          .from("ss_participants")
          .update({ must_reset_password: false })
          .eq("account_id", account.id)
          .eq("edition_id", account.edition_id);

      if (updateParticipantsError) {
        console.error("Participants reset update:", updateParticipantsError.message);
        return response({
          error: "Password cambiata, ma aggiornamento partecipanti non completato",
        }, 500);
      }

      return response({
        success: true,
        message: "Password cambiata correttamente",
        must_reset_password: false,
      });
    }

    // BLOCCO OBBLIGATORIO FINO AL CAMBIO PASSWORD
    if (account.must_reset_password && action !== "change_password") {
      return response({
        error: "Devi cambiare la password prima di continuare",
        must_reset_password: true,
      }, 403);
    }


    // WISHLIST DELLA PROPRIA FAMIGLIA
    if (action === "my_wishlists") {
      const { data: participants, error: participantsError } =
        await adminClient
          .from("ss_participants")
          .select("id, display_name")
          .eq("account_id", account.id)
          .eq("edition_id", account.edition_id)
          .order("display_name");

      if (participantsError) {
        console.error("My participants lookup:", participantsError.message);
        return response({ error: "Errore nel recupero partecipanti" }, 500);
      }

      const participantIds = (participants ?? []).map(item => item.id);
      const { data: wishlists, error: wishlistsError } = participantIds.length
        ? await adminClient
            .from("ss_wishlists")
            .select("participant_id, ciphertext, nonce")
            .in("participant_id", participantIds)
        : { data: [], error: null };

      if (wishlistsError) {
        console.error("My wishlists lookup:", wishlistsError.message);
        return response({ error: "Errore nel recupero delle wishlist" }, 500);
      }

      const wishlistByParticipant = new Map(
        (wishlists ?? []).map(item => [item.participant_id, item]),
      );

      const result = await Promise.all((participants ?? []).map(async participant => {
        const saved = wishlistByParticipant.get(participant.id);
        let gifts: unknown[] = [];

        if (saved) {
          gifts = await decryptWishlist(saved.ciphertext, saved.nonce);
        }

        return {
          participant_id: participant.id,
          display_name: participant.display_name,
          gifts,
        };
      }));

      return response({ success: true, wishlists: result });
    }

    // SALVATAGGIO DELLA WISHLIST DI UN PARTECIPANTE DELLA PROPRIA FAMIGLIA
    if (action === "save_wishlist") {
      const participantId = body.participant_id;
      const gifts = body.gifts;

      if (
        !validText(participantId) ||
        !Array.isArray(gifts) ||
        gifts.length > 30
      ) {
        return response({
          error: "La wishlist non è valida. Puoi inserire al massimo 30 idee regalo.",
        }, 400);
      }

      for (const gift of gifts) {
        if (
          !gift ||
          typeof gift !== "object" ||
          !validText(gift.name) ||
          gift.name.trim().length > 200
        ) {
          return response({ error: "Ogni regalo deve avere un nome valido." }, 400);
        }

        if (gift.url !== undefined && gift.url !== null && gift.url !== "") {
          if (
            typeof gift.url !== "string" ||
            gift.url.length > 2048
          ) {
            return response({ error: "Un link della wishlist non è valido." }, 400);
          }

          try {
            const parsedUrl = new URL(gift.url);
            if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
              return response({ error: "I link devono iniziare con http:// o https://." }, 400);
            }
          } catch {
            return response({ error: "Un link della wishlist non è valido." }, 400);
          }
        }
      }

      const { data: edition, error: editionError } =
        await adminClient
          .from("ss_editions")
          .select("wishlist_deadline")
          .eq("id", account.edition_id)
          .maybeSingle();

      if (editionError || !edition) {
        return response({ error: "Edizione non disponibile." }, 500);
      }

      if (
        edition.wishlist_deadline &&
        Date.now() > new Date(edition.wishlist_deadline).getTime()
      ) {
        return response({ error: "Il termine per modificare le wishlist è scaduto." }, 403);
      }

      const { data: participant, error: participantError } =
        await adminClient
          .from("ss_participants")
          .select("id")
          .eq("id", participantId)
          .eq("account_id", account.id)
          .eq("edition_id", account.edition_id)
          .maybeSingle();

      if (participantError || !participant) {
        return response({
          error: "Non puoi modificare la wishlist di questo partecipante.",
        }, 403);
      }

      const encrypted = await encryptWishlist(
        gifts.map(gift => ({
          name: gift.name.trim(),
          ...(gift.url ? { url: gift.url.trim() } : {}),
        })),
      );

      const { error: saveError } = await adminClient
        .from("ss_wishlists")
        .upsert({
          participant_id: participantId,
          ciphertext: encrypted.ciphertext,
          nonce: encrypted.nonce,
          key_version: encrypted.key_version,
          updated_at: new Date().toISOString(),
        }, { onConflict: "participant_id" });

      if (saveError) {
        console.error("Wishlist save:", saveError.message);
        return response({ error: "Non è stato possibile salvare la wishlist." }, 500);
      }

      return response({ success: true, message: "Wishlist salvata." });
    }

    // WISHLIST DEGLI ALTRI PARTECIPANTI: ESCLUDE SEMPRE LA PROPRIA FAMIGLIA
    // Per ogni regalo indica se è disponibile, già preso o scelto da te.
    if (action === "public_wishlists") {
      const { data: participants, error: participantsError } =
        await adminClient
          .from("ss_participants")
          .select("id, display_name")
          .eq("edition_id", account.edition_id)
          .neq("account_id", account.id)
          .order("display_name");

      if (participantsError) {
        console.error("Public participants lookup:", participantsError.message);
        return response({ error: "Errore nel recupero partecipanti" }, 500);
      }

      const assignmentMap = await loadAssignmentMap(account.edition_id);
      const allAssignments = [...assignmentMap.values()].map(
        receiver => ({ receiver_participant_id: receiver }),
      );

      const { data: selections, error: selectionsError } =
        await adminClient
          .from("ss_gift_selections")
          .select(
            "owner_participant_id, gift_key, selected_by_account_id, is_secret_santa_pick",
          )
          .eq("edition_id", account.edition_id);

      if (selectionsError) {
        console.error(
          "Assignments/selections lookup:",
          selectionsError.message,
        );
        return response({ error: "Errore nel recupero delle selezioni" }, 500);
      }

      const myAssignments = await loadMyAssignments(
        account.id,
        account.edition_id,
      );
      const giftsByParticipant = await loadGifts(
        (participants ?? []).map(item => item.id),
      );

      const hasSecretSanta = new Set(
        (allAssignments ?? []).map(item => item.receiver_participant_id),
      );
      const santaDecided = new Set(
        (selections ?? [])
          .filter(item => item.is_secret_santa_pick)
          .map(item => item.owner_participant_id),
      );
      const selectionByGift = new Map(
        (selections ?? []).map(item => [
          `${item.owner_participant_id}:${item.gift_key}`,
          item,
        ]),
      );
      // destinatario -> nomi dei miei familiari che devono fargli il regalo
      const myRecipients = new Map<string, string[]>();
      for (const item of myAssignments) {
        if (!item.receiver_participant_id) continue;
        const names = myRecipients.get(item.receiver_participant_id) ?? [];
        names.push(item.giver_name);
        myRecipients.set(item.receiver_participant_id, names);
      }

      const result = (participants ?? []).map(participant => {
        const isMyRecipient = myRecipients.has(participant.id);
        const canSelect =
          isMyRecipient ||
          (hasSecretSanta.has(participant.id) &&
            santaDecided.has(participant.id));

        let blockedReason: string | null = null;
        if (!canSelect) {
          blockedReason = hasSecretSanta.has(participant.id)
            ? "Il Secret Santa di questa persona non ha ancora deciso cosa regalare: i suoi regali non sono ancora selezionabili."
            : "L'estrazione non è ancora stata effettuata.";
        }

        const gifts = (giftsByParticipant.get(participant.id) ?? []).map(
          gift => {
            const selection = selectionByGift.get(
              `${participant.id}:${gift.gift_key}`,
            );

            return {
              ...gift,
              status: !selection
                ? "available"
                : selection.selected_by_account_id === account.id
                  ? "mine"
                  : "taken",
            };
          },
        );

        return {
          participant_id: participant.id,
          display_name: participant.display_name,
          gifts,
          is_my_recipient: isMyRecipient,
          recipient_for: myRecipients.get(participant.id) ?? [],
          can_select: canSelect,
          blocked_reason: blockedReason,
        };
      });

      // Il destinatario del proprio Secret Santa compare per primo
      result.sort((a, b) => {
        if (a.is_my_recipient !== b.is_my_recipient) {
          return a.is_my_recipient ? -1 : 1;
        }
        return a.display_name.localeCompare(b.display_name, "it");
      });

      return response({
        success: true,
        wishlists: result,
        my_assignments: myAssignments,
      });
    }

    // A CHI DEVONO FARE IL REGALO I MIEI PARTECIPANTI
    if (action === "my_assignments") {
      const myAssignments = await loadMyAssignments(
        account.id,
        account.edition_id,
      );

      const receiverIds = myAssignments
        .map(item => item.receiver_participant_id)
        .filter((id): id is string => !!id);
      const giftsByParticipant = await loadGifts(receiverIds);

      return response({
        success: true,
        assignments: myAssignments.map(item => ({
          ...item,
          gifts: item.receiver_participant_id
            ? (giftsByParticipant.get(item.receiver_participant_id) ?? [])
                .map(({ name, url }) => ({ name, ...(url ? { url } : {}) }))
            : [],
        })),
      });
    }

    // SELEZIONE DI UN REGALO DALLA WISHLIST DI UN ALTRO PARTECIPANTE
    if (action === "select_gift") {
      const ownerId = body.participant_id;
      const selectedKey = body.gift_key;

      if (!validText(ownerId) || !validText(selectedKey)) {
        return response({ error: "Richiesta non valida." }, 400);
      }

      const { data: owner, error: ownerError } = await adminClient
        .from("ss_participants")
        .select("id, display_name, account_id")
        .eq("id", ownerId)
        .eq("edition_id", account.edition_id)
        .maybeSingle();

      if (ownerError || !owner) {
        return response({ error: "Partecipante non trovato." }, 404);
      }

      if (owner.account_id === account.id) {
        return response({
          error: "Non puoi selezionare i regali della tua famiglia.",
        }, 403);
      }

      // Il regalo deve esistere davvero nella wishlist attuale
      const gifts = (await loadGifts([owner.id])).get(owner.id) ?? [];
      if (!gifts.some(gift => gift.gift_key === selectedKey)) {
        return response({
          error: "Questo regalo non è più nella wishlist. Aggiorna la pagina.",
        }, 409);
      }

      const assignmentMap = await loadAssignmentMap(account.edition_id);
      const giverOfOwner = [...assignmentMap.entries()].find(
        ([, receiverId]) => receiverId === owner.id,
      )?.[0];
      const assignment = giverOfOwner
        ? { giver_participant_id: giverOfOwner }
        : null;

      if (!assignment) {
        return response({
          error: "L'estrazione non è ancora stata effettuata.",
        }, 403);
      }

      // Sono io (o un mio familiare) il Secret Santa di questa persona?
      const { data: giver, error: giverError } = await adminClient
        .from("ss_participants")
        .select("account_id")
        .eq("id", assignment.giver_participant_id)
        .maybeSingle();

      if (giverError || !giver) {
        return response({ error: "Errore nel controllo dell'assegnazione." }, 500);
      }

      const isSecretSanta = giver.account_id === account.id;

      if (!isSecretSanta) {
        const { count, error: decidedError } = await adminClient
          .from("ss_gift_selections")
          .select("id", { count: "exact", head: true })
          .eq("owner_participant_id", owner.id)
          .eq("is_secret_santa_pick", true);

        if (decidedError) {
          return response({ error: "Errore nel controllo delle selezioni." }, 500);
        }

        if (!count) {
          return response({
            error: "Il Secret Santa di questa persona non ha ancora deciso cosa regalare.",
          }, 403);
        }
      }

      const { error: insertError } = await adminClient
        .from("ss_gift_selections")
        .insert({
          edition_id: account.edition_id,
          owner_participant_id: owner.id,
          gift_key: selectedKey,
          selected_by_account_id: account.id,
          is_secret_santa_pick: isSecretSanta,
        });

      if (insertError) {
        if (insertError.code === "23505") {
          return response({
            error: "Questo regalo è già stato selezionato da qualcun altro.",
          }, 409);
        }
        console.error("Gift selection:", insertError.message);
        return response({ error: "Non è stato possibile selezionare il regalo." }, 500);
      }

      return response({ success: true, message: "Regalo selezionato." });
    }

    // ANNULLAMENTO DI UNA PROPRIA SELEZIONE
    if (action === "release_gift") {
      const ownerId = body.participant_id;
      const selectedKey = body.gift_key;

      if (!validText(ownerId) || !validText(selectedKey)) {
        return response({ error: "Richiesta non valida." }, 400);
      }

      const { error: releaseError } = await adminClient
        .from("ss_gift_selections")
        .delete()
        .eq("edition_id", account.edition_id)
        .eq("owner_participant_id", ownerId)
        .eq("gift_key", selectedKey)
        .eq("selected_by_account_id", account.id);

      if (releaseError) {
        console.error("Gift release:", releaseError.message);
        return response({ error: "Non è stato possibile annullare la selezione." }, 500);
      }

      return response({ success: true, message: "Selezione annullata." });
    }

    // AZIONI RISERVATE ALL'AMMINISTRATORE
    if (typeof action === "string" && action.startsWith("admin_")) {
      if (account.role !== "admin") {
        return response({ error: "Azione riservata all'amministratore." }, 403);
      }

      // ELENCO UTENTI
      if (action === "admin_list_users") {
        const { data: accounts, error: accountsError } = await adminClient
          .from("ss_accounts")
          .select("id, login_name, role, must_reset_password, created_at")
          .eq("edition_id", account.edition_id)
          .order("login_name");

        const { data: participants, error: participantsError } =
          await adminClient
            .from("ss_participants")
            .select("id, account_id, display_name, participant_type")
            .eq("edition_id", account.edition_id)
            .order("display_name");

        const assignmentsCount =
          (await loadAssignmentMap(account.edition_id)).size;

        if (accountsError || participantsError) {
          console.error(
            "Admin list users:",
            accountsError?.message ?? participantsError?.message,
          );
          return response({ error: "Errore nel recupero degli utenti" }, 500);
        }

        return response({
          success: true,
          current_account_id: account.id,
          draw_done: (assignmentsCount ?? 0) > 0,
          users: (accounts ?? []).map(item => ({
            ...item,
            participants: (participants ?? [])
              .filter(p => p.account_id === item.id)
              .map(p => ({
                id: p.id,
                display_name: p.display_name,
                participant_type: p.participant_type,
              })),
          })),
        });
      }

      // AGGIUNTA MANUALE DI UN UTENTE
      if (action === "admin_create_user") {
        const adultName = body.name;
        const children = body.children ?? [];
        const suppliedPassword = body.password;

        if (
          !validText(adultName) ||
          adultName.trim().length > 100 ||
          !Array.isArray(children) ||
          children.length > 10 ||
          (validText(suppliedPassword) &&
            (suppliedPassword.length < 6 || suppliedPassword.length > 128))
        ) {
          return response({
            error: "Controlla nome, password (almeno 6 caratteri) e numero dei figli.",
          }, 400);
        }

        const childNames: string[] = [];
        for (const child of children) {
          if (!validText(child) || child.trim().length > 100) {
            return response({ error: "Uno dei nomi dei figli non è valido." }, 400);
          }
          childNames.push(child.trim());
        }

        // Se l'admin non sceglie una password, ne viene generata una
        // temporanea: l'utente dovrà cambiarla al primo accesso.
        const tempPassword = validText(suppliedPassword)
          ? suppliedPassword
          : generateTempPassword();

        const created = await createFamilyAccount({
          editionId: account.edition_id,
          adultName: adultName.trim(),
          childNames,
          password: tempPassword,
          mustResetPassword: true,
        });

        if ("error" in created) {
          return response({ error: created.error }, created.status);
        }

        return response({
          success: true,
          message: "Utente creato.",
          login_name: adultName.trim(),
          temp_password: tempPassword,
        }, 201);
      }

      // RESET PASSWORD: password temporanea da comunicare a voce
      if (action === "admin_reset_password") {
        const targetId = body.account_id;

        if (!validText(targetId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        if (targetId === account.id) {
          return response({
            error: "Non puoi resettare la password del tuo stesso account da qui.",
          }, 400);
        }

        const { data: target, error: targetError } = await adminClient
          .from("ss_accounts")
          .select("id, login_name, auth_user_id")
          .eq("id", targetId)
          .eq("edition_id", account.edition_id)
          .maybeSingle();

        if (targetError || !target || !target.auth_user_id) {
          return response({ error: "Utente non trovato." }, 404);
        }

        const tempPassword = generateTempPassword();

        const { error: passwordError } =
          await adminClient.auth.admin.updateUserById(
            target.auth_user_id,
            { password: tempPassword },
          );

        if (passwordError) {
          console.error("Admin reset password:", passwordError.message);
          return response({ error: "Errore nel reset della password." }, 500);
        }

        const { error: flagError } = await adminClient
          .from("ss_accounts")
          .update({ must_reset_password: true })
          .eq("id", target.id);

        const { error: participantsFlagError } = await adminClient
          .from("ss_participants")
          .update({ must_reset_password: true })
          .eq("account_id", target.id)
          .eq("edition_id", account.edition_id);

        if (flagError || participantsFlagError) {
          console.error(
            "Admin reset flags:",
            flagError?.message ?? participantsFlagError?.message,
          );
          return response({
            error: "Password cambiata, ma l'obbligo di cambio al primo accesso non è stato impostato.",
          }, 500);
        }

        return response({
          success: true,
          login_name: target.login_name,
          temp_password: tempPassword,
        });
      }

      // ELIMINAZIONE DI UN UTENTE (con i suoi partecipanti e dati collegati)
      if (action === "admin_delete_user") {
        const targetId = body.account_id;

        if (!validText(targetId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        if (targetId === account.id) {
          return response({
            error: "Non puoi eliminare il tuo stesso account.",
          }, 400);
        }

        const { data: target, error: targetError } = await adminClient
          .from("ss_accounts")
          .select("id, login_name, auth_user_id")
          .eq("id", targetId)
          .eq("edition_id", account.edition_id)
          .maybeSingle();

        if (targetError || !target) {
          return response({ error: "Utente non trovato." }, 404);
        }

        const { data: targetParticipants, error: targetParticipantsError } =
          await adminClient
            .from("ss_participants")
            .select("id")
            .eq("account_id", target.id)
            .eq("edition_id", account.edition_id);

        if (targetParticipantsError) {
          return response({ error: "Errore nel recupero dei partecipanti." }, 500);
        }

        const ids = (targetParticipants ?? []).map(item => item.id);

        let drawAffected = false;

        if (ids.length) {
          // righe dell'estrazione da togliere: quelle di chi viene eliminato
          // e quelle di chi avrebbe dovuto fargli il regalo
          const assignmentMap = await loadAssignmentMap(account.edition_id);
          const idSet = new Set(ids);
          const assignmentRowsToDelete = [...assignmentMap.entries()]
            .filter(([giver, receiver]) => idSet.has(giver) || idSet.has(receiver))
            .map(([giver]) => giver);
          drawAffected = assignmentRowsToDelete.length > 0;

          const cleanup = [
            adminClient.from("ss_wishlists").delete().in("participant_id", ids),
            adminClient.from("ss_gift_selections").delete().in("owner_participant_id", ids),
            adminClient.from("ss_assignments").delete().in("participant_id", [...ids, ...assignmentRowsToDelete]),
          ];

          for (const result of await Promise.all(cleanup)) {
            if (result.error) {
              console.error("Admin delete cleanup:", result.error.message);
              return response({ error: "Errore nella pulizia dei dati dell'utente." }, 500);
            }
          }
        }

        // le selezioni fatte da questo utente rendono di nuovo disponibili i regali
        const { error: ownSelectionsError } = await adminClient
          .from("ss_gift_selections")
          .delete()
          .eq("selected_by_account_id", target.id);

        if (ownSelectionsError) {
          console.error("Admin delete selections:", ownSelectionsError.message);
          return response({ error: "Errore nella pulizia dei dati dell'utente." }, 500);
        }

        const { error: deleteParticipantsError } = await adminClient
          .from("ss_participants")
          .delete()
          .eq("account_id", target.id)
          .eq("edition_id", account.edition_id);

        if (deleteParticipantsError) {
          console.error("Admin delete participants:", deleteParticipantsError.message);
          return response({ error: "Errore nell'eliminazione dei partecipanti." }, 500);
        }

        const { error: deleteAccountError } = await adminClient
          .from("ss_accounts")
          .delete()
          .eq("id", target.id);

        if (deleteAccountError) {
          console.error("Admin delete account:", deleteAccountError.message);
          return response({ error: "Errore nell'eliminazione dell'account." }, 500);
        }

        if (target.auth_user_id) {
          const { error: deleteAuthError } =
            await adminClient.auth.admin.deleteUser(target.auth_user_id);
          if (deleteAuthError) {
            console.error("Admin delete auth user:", deleteAuthError.message);
          }
        }

        return response({
          success: true,
          message: `Utente "${target.login_name}" eliminato.`,
          draw_affected: drawAffected,
        });
      }

      // RESET DELL'ESTRAZIONE: toglie le assegnazioni e tutti i regali scelti
      if (action === "admin_reset_draw") {
        const { data: everyone, error: everyoneError } = await adminClient
          .from("ss_participants")
          .select("id")
          .eq("edition_id", account.edition_id);

        if (everyoneError) {
          return response({ error: "Errore nel recupero partecipanti." }, 500);
        }

        const allIds = (everyone ?? []).map(item => item.id);

        const { error: clearSelectionsError } = await adminClient
          .from("ss_gift_selections")
          .delete()
          .eq("edition_id", account.edition_id);

        const { error: clearAssignmentsError } = allIds.length
          ? await adminClient
              .from("ss_assignments")
              .delete()
              .in("participant_id", allIds)
          : { error: null };

        if (clearSelectionsError || clearAssignmentsError) {
          console.error(
            "Admin reset draw:",
            clearSelectionsError?.message ?? clearAssignmentsError?.message,
          );
          return response({ error: "Non è stato possibile resettare l'estrazione." }, 500);
        }

        return response({
          success: true,
          message: "Estrazione resettata: assegnazioni e regali scelti sono stati cancellati.",
        });
      }

      // ESTRAZIONE DEL SECRET SANTA
      if (action === "admin_draw") {
        const { data: everyone, error: everyoneError } = await adminClient
          .from("ss_participants")
          .select("id, account_id")
          .eq("edition_id", account.edition_id);

        if (everyoneError) {
          return response({ error: "Errore nel recupero partecipanti." }, 500);
        }

        const people = everyone ?? [];

        if (people.length < 2) {
          return response({
            error: "Servono almeno due partecipanti per fare l'estrazione.",
          }, 400);
        }

        const existing = (await loadAssignmentMap(account.edition_id)).size;

        if (existing > 0 && body.confirm_redo !== true) {
          return response({
            error: "L'estrazione è già stata fatta. Ripeterla cancella anche tutte le selezioni dei regali.",
            needs_confirmation: true,
          }, 409);
        }

        // Nessuno pesca sé stesso né qualcuno della propria famiglia
        let receivers: typeof people | null = null;

        for (let attempt = 0; attempt < 5000 && !receivers; attempt++) {
          const shuffled = [...people];
          for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
          }

          if (people.every((p, i) => p.account_id !== shuffled[i].account_id)) {
            receivers = shuffled;
          }
        }

        if (!receivers) {
          return response({
            error: "Non è possibile fare un'estrazione valida: una famiglia ha troppi partecipanti rispetto agli altri.",
          }, 400);
        }

        // ogni riga è cifrata: dal database non si legge chi pesca chi
        const rows = await Promise.all(people.map(async (giver, index) => {
          const encrypted = await encryptWishlist([
            { receiver_participant_id: receivers![index].id },
          ]);

          return {
            participant_id: giver.id,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            key_version: encrypted.key_version,
          };
        }));

        const { error: clearSelectionsError } = await adminClient
          .from("ss_gift_selections")
          .delete()
          .eq("edition_id", account.edition_id);

        const { error: clearAssignmentsError } = await adminClient
          .from("ss_assignments")
          .delete()
          .in("participant_id", people.map(person => person.id));

        if (clearSelectionsError || clearAssignmentsError) {
          console.error(
            "Admin draw clear:",
            clearSelectionsError?.message ?? clearAssignmentsError?.message,
          );
          return response({ error: "Errore nella preparazione dell'estrazione." }, 500);
        }

        const { error: insertAssignmentsError } = await adminClient
          .from("ss_assignments")
          .insert(rows);

        if (insertAssignmentsError) {
          console.error("Admin draw insert:", insertAssignmentsError.message);
          return response({ error: "Errore nel salvataggio dell'estrazione." }, 500);
        }

        return response({
          success: true,
          message: `Estrazione completata per ${rows.length} partecipanti.`,
        });
      }

      return response({ error: "Azione non riconosciuta" }, 400);
    }

    // DATI ACCOUNT
    if (action === "whoami") {
      const { data: edition, error: editionError } =
        await adminClient
          .from("ss_editions")
          .select(
            "id, year, status, registration_deadline, wishlist_deadline",
          )
          .eq("id", account.edition_id)
          .maybeSingle();

      if (editionError) {
        console.error("Edition lookup:", editionError.message);
        return response({ error: "Errore nel recupero edizione" }, 500);
      }

      const { data: participants, error: participantsError } =
        await adminClient
          .from("ss_participants")
          .select("id, display_name, must_reset_password")
          .eq("account_id", account.id)
          .eq("edition_id", account.edition_id)
          .order("display_name");

      if (participantsError) {
        console.error("Participants lookup:", participantsError.message);
        return response({ error: "Errore nel recupero partecipanti" }, 500);
      }

      return response({
        success: true,
        account: {
          id: account.id,
          login_name: account.login_name,
          role: account.role,
          must_reset_password: account.must_reset_password,
        },
        edition,
        participants: participants ?? [],
      });
    }

    return response({ error: "Azione non riconosciuta" }, 400);
  } catch (error) {
    console.error("Function error:", error);
    return response({ error: "Richiesta non valida" }, 400);
  }
});
