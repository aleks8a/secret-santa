
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

// Nome utente: solo lettere, numeri, trattino e trattino basso, max 20, senza spazi.
const LOGIN_NAME_PATTERN = /^[A-Za-z0-9_-]{1,20}$/;
const LOGIN_NAME_ERROR =
  "Il nome utente può contenere solo lettere, numeri, trattino (-) e trattino basso (_), senza spazi, massimo 20 caratteri.";

// Rivelazione dei Secret Santa: 25 dicembre 2026, ore 00:00 (Italia)
const REVEAL_AT = new Date("2026-12-25T00:00:00+01:00");

// ilike tratta % e _ come caratteri jolly: li neutralizza per un confronto esatto
function escapeLike(value: string) {
  return value.replace(/[\\%_]/g, "\\$&");
}

// Valida una lista di regali (usata sia dall'utente sia dall'admin).
// Restituisce un messaggio di errore, oppure null se la lista è valida.
function validateGifts(gifts: unknown): string | null {
  if (!Array.isArray(gifts) || gifts.length > 30) {
    return "La wishlist non è valida. Puoi inserire al massimo 30 idee regalo.";
  }

  for (const gift of gifts) {
    if (
      !gift ||
      typeof gift !== "object" ||
      !validText(gift.name) ||
      gift.name.trim().length > 200
    ) {
      return "Ogni regalo deve avere un nome valido.";
    }

    if (gift.url !== undefined && gift.url !== null && gift.url !== "") {
      if (typeof gift.url !== "string" || gift.url.length > 2048) {
        return "Un link della wishlist non è valido.";
      }

      try {
        const parsedUrl = new URL(gift.url);
        if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
          return "I link devono iniziare con http:// o https://.";
        }
      } catch {
        return "Un link della wishlist non è valido.";
      }
    }
  }

  return null;
}

function cleanGifts(gifts: { name: string; url?: string | null }[]) {
  return gifts.map(gift => ({
    name: gift.name.trim(),
    ...(gift.url ? { url: gift.url.trim() } : {}),
  }));
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

// Registro delle attività (visibile all'admin). Non deve mai bloccare l'azione
// principale: se la scrittura fallisce si registra solo l'errore.
async function logActivity(
  editionId: string,
  event: string,
  accountName: string | null,
  details?: string,
) {
  try {
    const { error } = await adminClient.from("ss_activity_log").insert({
      edition_id: editionId,
      event,
      account_name: accountName,
      details: details ?? null,
    });
    if (error) console.error("Activity log:", error.message);
  } catch (error) {
    console.error("Activity log:", error);
  }
}

// Toglie wishlist, selezioni e assegnazioni dei partecipanti indicati
// (e le assegnazioni di chi avrebbe dovuto fargli il regalo), poi li elimina.
async function removeParticipants(ids: string[], editionId: string) {
  if (!ids.length) return { error: null as string | null, drawAffected: false };

  const assignmentMap = await loadAssignmentMap(editionId);
  const idSet = new Set(ids);
  const assignmentRowsToDelete = [...assignmentMap.entries()]
    .filter(([giver, receiver]) => idSet.has(giver) || idSet.has(receiver))
    .map(([giver]) => giver);

  const cleanup = [
    adminClient.from("ss_wishlists").delete().in("participant_id", ids),
    adminClient.from("ss_gift_selections").delete().in("owner_participant_id", ids),
    adminClient.from("ss_assignments").delete().in(
      "participant_id",
      [...ids, ...assignmentRowsToDelete],
    ),
  ];

  for (const result of await Promise.all(cleanup)) {
    if (result.error) {
      console.error("Remove participants cleanup:", result.error.message);
      return { error: "Errore nella pulizia dei dati.", drawAffected: false };
    }
  }

  // i divieti che riguardano queste persone non servono più
  const idList = ids.join(",");
  const { error: restrictionCleanupError } = await adminClient
    .from("ss_draw_restrictions")
    .delete()
    .eq("edition_id", editionId)
    .or(`participant_a.in.(${idList}),participant_b.in.(${idList})`);
  if (restrictionCleanupError) {
    console.error("Restrictions cleanup:", restrictionCleanupError.message);
  }

  const { error: deleteError } = await adminClient
    .from("ss_participants")
    .delete()
    .in("id", ids)
    .eq("edition_id", editionId);

  if (deleteError) {
    console.error("Remove participants:", deleteError.message);
    return { error: "Errore nell'eliminazione dei partecipanti.", drawAffected: false };
  }

  return { error: null as string | null, drawAffected: assignmentRowsToDelete.length > 0 };
}

// Elimina un account con tutti i suoi partecipanti e dati collegati.
async function deleteAccountCascade(
  target: { id: string; auth_user_id: string | null },
  editionId: string,
) {
  const { data: targetParticipants, error: targetParticipantsError } =
    await adminClient
      .from("ss_participants")
      .select("id")
      .eq("account_id", target.id)
      .eq("edition_id", editionId);

  if (targetParticipantsError) {
    return { error: "Errore nel recupero dei partecipanti.", drawAffected: false };
  }

  const removed = await removeParticipants(
    (targetParticipants ?? []).map(item => item.id),
    editionId,
  );
  if (removed.error) return removed;

  // le selezioni fatte da questo utente rendono di nuovo disponibili i regali
  const { error: ownSelectionsError } = await adminClient
    .from("ss_gift_selections")
    .delete()
    .eq("selected_by_account_id", target.id);

  if (ownSelectionsError) {
    console.error("Delete account selections:", ownSelectionsError.message);
    return { error: "Errore nella pulizia dei dati dell'utente.", drawAffected: removed.drawAffected };
  }

  const { error: deleteAccountError } = await adminClient
    .from("ss_accounts")
    .delete()
    .eq("id", target.id);

  if (deleteAccountError) {
    console.error("Delete account:", deleteAccountError.message);
    return { error: "Errore nell'eliminazione dell'account.", drawAffected: removed.drawAffected };
  }

  if (target.auth_user_id) {
    const { error: deleteAuthError } =
      await adminClient.auth.admin.deleteUser(target.auth_user_id);
    if (deleteAuthError) {
      console.error("Delete auth user:", deleteAuthError.message);
    }
  }

  return { error: null as string | null, drawAffected: removed.drawAffected };
}

// Chiave di una coppia vietata: vale in entrambe le direzioni.
function pairKey(a: string, b: string) {
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

// Trova per ogni persona chi deve pescare: mai sé stessa, mai un familiare,
// mai una coppia vietata. Restituisce null se non esiste una soluzione.
function findAssignment<T extends { id: string; account_id: string }>(
  people: T[],
  forbidden: Set<string>,
): T[] | null {
  const shuffle = <U,>(items: U[]) => {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  };

  const allowed = (giver: T, receiver: T) =>
    giver.account_id !== receiver.account_id &&
    !forbidden.has(pairKey(giver.id, receiver.id));

  for (let restart = 0; restart < 60; restart++) {
    const givers = shuffle(people);
    const used = new Set<string>();
    const result = new Map<string, T>();
    let steps = 0;

    const solve = (index: number): boolean => {
      if (index === givers.length) return true;
      if (++steps > 20000) return false;

      const giver = givers[index];
      for (const receiver of shuffle(people)) {
        if (used.has(receiver.id) || !allowed(giver, receiver)) continue;
        used.add(receiver.id);
        result.set(giver.id, receiver);
        if (solve(index + 1)) return true;
        used.delete(receiver.id);
        result.delete(giver.id);
      }
      return false;
    };

    if (solve(0)) return people.map(person => result.get(person.id)!);
  }

  return null;
}

async function isDrawDone(editionId: string) {
  return (await loadAssignmentMap(editionId)).size > 0;
}

// true se il nome è già usato da un account o un partecipante dell'edizione
async function nameInUse(editionId: string, name: string) {
  const lower = name.toLocaleLowerCase("it");
  const [{ data: accounts }, { data: participants }] = await Promise.all([
    adminClient.from("ss_accounts").select("login_name").eq("edition_id", editionId),
    adminClient.from("ss_participants").select("display_name").eq("edition_id", editionId),
  ]);

  return [
    ...(accounts ?? []).map(item => item.login_name),
    ...(participants ?? []).map(item => item.display_name),
  ].some(existing => existing.toLocaleLowerCase("it") === lower);
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

      if (!LOGIN_NAME_PATTERN.test(normalizedAdultName)) {
        return response({ error: LOGIN_NAME_ERROR }, 400);
      }

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

      if (await isDrawDone(edition.id)) {
        return response({
          error: "L'estrazione è già stata fatta: le iscrizioni sono chiuse.",
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

      await logActivity(
        edition.id,
        "register",
        normalizedAdultName,
        childNames.length ? `con ${childNames.length} figli` : undefined,
      );

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

    // PASSWORD DIMENTICATA: segnala all'admin che serve un reset.
    // La risposta è sempre la stessa, esista o no il nome utente, così
    // non si può usare questa azione per scoprire chi è registrato.
    if (action === "request_password_reset") {
      const loginName = body.login_name;

      if (
        !validText(loginName) ||
        loginName.length > 100
      ) {
        return response({ error: "Inserisci il tuo nome utente." }, 400);
      }

      const { data: target } = await adminClient
        .from("ss_accounts")
        .select("id, edition_id, login_name, role, password_reset_requested_at")
        .ilike("login_name", escapeLike(loginName.trim()))
        .maybeSingle();

      // l'admin non può chiedere il reset a sé stesso
      if (target && target.role !== "admin" && !target.password_reset_requested_at) {
        const { error: requestError } = await adminClient
          .from("ss_accounts")
          .update({ password_reset_requested_at: new Date().toISOString() })
          .eq("id", target.id);

        if (requestError) {
          console.error("Password reset request:", requestError.message);
          return response({ error: "Non è stato possibile inviare la richiesta." }, 500);
        }

        await logActivity(target.edition_id, "reset_request", target.login_name);
      }

      return response({
        success: true,
        message:
          "Richiesta inviata. Se il nome utente è corretto, l'amministratore è stato avvisato e ti darà una password temporanea.",
      });
    }

    // INFO PUBBLICHE PER IL COUNTDOWN (visibili anche prima dell'accesso)
    if (action === "public_info") {
      const { data: edition } = await adminClient
        .from("ss_editions")
        .select("id, draw_date, registration_deadline")
        .eq("year", 2026)
        .maybeSingle();

      if (!edition) return response({ error: "Edizione non disponibile." }, 500);

      return response({
        success: true,
        draw_done: await isDrawDone(edition.id),
        draw_date: edition.draw_date ?? edition.registration_deadline ?? null,
        reveal_at: REVEAL_AT.toISOString(),
      });
    }

    // LOGIN: nome utente + password
    if (action === "login") {
      const loginName = body.login_name;
      const password = body.password;

      if (
        !validText(loginName) ||
        !validText(password) ||
        loginName.length > 100
      ) {
        return response({ error: "Credenziali non valide" }, 400);
      }

      const { data: account, error: accountError } =
        await adminClient
          .from("ss_accounts")
          .select("id, auth_user_id")
          .ilike("login_name", escapeLike(loginName.trim()))
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
          .select("id, edition_id, login_name, role, must_reset_password")
          .eq("id", account.id)
          .single();

      if (accountDataError || !accountData) {
        return response({ error: "Errore nel recupero account" }, 500);
      }

      // se la password si è ricordata, la richiesta di reset non serve più
      await adminClient
        .from("ss_accounts")
        .update({ password_reset_requested_at: null })
        .eq("id", account.id)
        .not("password_reset_requested_at", "is", null);

      await logActivity(accountData.edition_id, "login", accountData.login_name);

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
          .update({
            must_reset_password: false,
            password_reset_requested_at: null,
          })
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

      await logActivity(account.edition_id, "password_change", account.login_name);

      return response({
        success: true,
        message: "Password cambiata correttamente",
        must_reset_password: false,
      });
    }

    // USCITA (solo per il registro attività)
    if (action === "logout") {
      await logActivity(account.edition_id, "logout", account.login_name);
      return response({ success: true });
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

      const giftsError = validateGifts(gifts);

      if (!validText(participantId) || giftsError) {
        return response({
          error: giftsError ??
            "La wishlist non è valida. Puoi inserire al massimo 30 idee regalo.",
        }, 400);
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

      const encrypted = await encryptWishlist(cleanGifts(gifts));

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
          .eq("excluded_from_draw", false)
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
              is_secret_santa_pick: selection?.is_secret_santa_pick === true,
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

    // MODIFICA PASSWORD (chiede la password attuale)
    if (action === "change_my_password") {
      const currentPassword = body.current_password;
      const newPassword = body.new_password;

      if (
        !validText(currentPassword) ||
        !validText(newPassword) ||
        newPassword.length < 6 ||
        newPassword.length > 128
      ) {
        return response({
          error: "La nuova password deve avere almeno 6 caratteri.",
        }, 400);
      }

      const { data: authUser } =
        await adminClient.auth.admin.getUserById(user.id);

      if (!authUser?.user?.email) {
        return response({ error: "Errore nel cambio password." }, 500);
      }

      const checkClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const { error: checkError } = await checkClient.auth.signInWithPassword({
        email: authUser.user.email,
        password: currentPassword,
      });

      if (checkError) {
        return response({ error: "La password attuale non è corretta." }, 403);
      }

      const { error: updateError } = await adminClient.auth.admin
        .updateUserById(user.id, { password: newPassword });

      if (updateError) {
        console.error("Password change:", updateError.message);
        return response({ error: "Errore nel cambio password." }, 500);
      }

      await adminClient
        .from("ss_accounts")
        .update({ password_reset_requested_at: null })
        .eq("id", account.id);

      await logActivity(account.edition_id, "password_change", account.login_name);

      return response({ success: true, message: "Password modificata." });
    }

    // RIVELAZIONE: chi era il Secret Santa di chi (dal 25 dicembre, ore 00:00)
    if (action === "reveal_secret_santas") {
      if (Date.now() < REVEAL_AT.getTime()) {
        return response({ error: "La rivelazione non è ancora disponibile." }, 403);
      }

      const assignmentMap = await loadAssignmentMap(account.edition_id);
      const { data: people } = await adminClient
        .from("ss_participants")
        .select("id, display_name")
        .eq("edition_id", account.edition_id);

      const nameById = new Map((people ?? []).map(p => [p.id, p.display_name]));
      const pairs = [...assignmentMap.entries()]
        .map(([giver, receiver]) => ({
          giver: nameById.get(giver) ?? "?",
          receiver: nameById.get(receiver) ?? "?",
        }))
        .sort((a, b) => a.giver.localeCompare(b.giver, "it"));

      return response({ success: true, account_id: account.id, pairs });
    }

    // UN GENITORE INCLUDE/ESCLUDE UN PROPRIO FIGLIO DAL SORTEGGIO
    if (action === "set_child_excluded") {
      const participantId = body.participant_id;
      const excluded = body.excluded;

      if (!validText(participantId) || typeof excluded !== "boolean") {
        return response({ error: "Richiesta non valida." }, 400);
      }

      if (await isDrawDone(account.edition_id)) {
        return response({
          error: "L'estrazione è già stata fatta: per cambiare chi partecipa l'amministratore deve prima resettarla.",
        }, 409);
      }

      const { data: updated, error: excludeError } = await adminClient
        .from("ss_participants")
        .update({ excluded_from_draw: excluded })
        .eq("id", participantId)
        .eq("account_id", account.id)
        .eq("edition_id", account.edition_id)
        .eq("participant_type", "minor")
        .select("id");

      if (excludeError) {
        console.error("Set child excluded:", excludeError.message);
        return response({ error: "Non è stato possibile aggiornare il figlio." }, 500);
      }

      if (!updated?.length) {
        return response({ error: "Puoi modificare solo i tuoi figli." }, 403);
      }

      return response({ success: true });
    }

    // LA MIA FAMIGLIA: componenti dell'account e stato dell'estrazione
    if (action === "my_family") {
      const { data: members, error: membersError } = await adminClient
        .from("ss_participants")
        .select("id, display_name, participant_type, excluded_from_draw")
        .eq("account_id", account.id)
        .eq("edition_id", account.edition_id)
        .order("display_name");

      if (membersError) {
        console.error("My family lookup:", membersError.message);
        return response({ error: "Errore nel recupero della famiglia" }, 500);
      }

      return response({
        success: true,
        role: account.role,
        draw_done: await isDrawDone(account.edition_id),
        members: members ?? [],
      });
    }

    // AGGIUNTA DI UN FIGLIO (prima dell'estrazione)
    if (action === "add_child") {
      const childName = body.name;

      if (!validText(childName) || childName.trim().length > 100) {
        return response({ error: "Inserisci un nome valido per il figlio/a." }, 400);
      }

      if (await isDrawDone(account.edition_id)) {
        return response({
          error: "L'estrazione è già stata fatta: per aggiungere un figlio l'amministratore deve prima resettarla.",
        }, 409);
      }

      const { count: childCount } = await adminClient
        .from("ss_participants")
        .select("id", { count: "exact", head: true })
        .eq("account_id", account.id)
        .eq("edition_id", account.edition_id)
        .eq("participant_type", "minor");

      if ((childCount ?? 0) >= 10) {
        return response({ error: "Puoi inserire al massimo 10 figli." }, 400);
      }

      const normalized = childName.trim();

      if (await nameInUse(account.edition_id, normalized)) {
        return response({
          error: `Il nome "${normalized}" è già utilizzato. Scegli un nome diverso.`,
        }, 409);
      }

      const { error: addError } = await adminClient
        .from("ss_participants")
        .insert({
          id: crypto.randomUUID(),
          edition_id: account.edition_id,
          account_id: account.id,
          display_name: normalized,
          participant_type: "minor",
          must_reset_password: false,
          created_at: new Date().toISOString(),
        });

      if (addError) {
        console.error("Add child:", addError.message);
        return response({ error: "Non è stato possibile aggiungere il figlio." }, 409);
      }

      await logActivity(account.edition_id, "child_add", account.login_name, normalized);

      return response({ success: true, message: `${normalized} è stato aggiunto.` });
    }

    // RIMOZIONE DI UN PROPRIO FIGLIO (prima dell'estrazione)
    if (action === "remove_child") {
      const participantId = body.participant_id;

      if (!validText(participantId)) {
        return response({ error: "Richiesta non valida." }, 400);
      }

      if (await isDrawDone(account.edition_id)) {
        return response({
          error: "L'estrazione è già stata fatta: per togliere un figlio l'amministratore deve prima resettarla.",
        }, 409);
      }

      const { data: child, error: childError } = await adminClient
        .from("ss_participants")
        .select("id, display_name, participant_type")
        .eq("id", participantId)
        .eq("account_id", account.id)
        .eq("edition_id", account.edition_id)
        .maybeSingle();

      if (childError || !child || child.participant_type !== "minor") {
        return response({ error: "Puoi togliere solo i tuoi figli." }, 403);
      }

      const removed = await removeParticipants([child.id], account.edition_id);
      if (removed.error) return response({ error: removed.error }, 500);

      await logActivity(account.edition_id, "child_remove", account.login_name, child.display_name);

      return response({ success: true, message: `${child.display_name} è stato tolto.` });
    }

    // AUTO-ELIMINAZIONE DEL PROPRIO ACCOUNT (non per l'amministratore)
    if (action === "delete_my_account") {
      if (account.role === "admin") {
        return response({ error: "L'amministratore non può eliminare il proprio account." }, 403);
      }

      if (await isDrawDone(account.edition_id)) {
        return response({
          error: "L'estrazione è già stata fatta: chiedi all'amministratore di eliminare il tuo account.",
        }, 409);
      }

      const deleted = await deleteAccountCascade(
        { id: account.id, auth_user_id: user.id },
        account.edition_id,
      );
      if (deleted.error) return response({ error: deleted.error }, 500);

      await logActivity(account.edition_id, "delete", account.login_name, "account eliminato dall'utente");

      return response({ success: true, message: "Il tuo account è stato eliminato." });
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
          .select(
            "id, login_name, role, must_reset_password, password_reset_requested_at, created_at",
          )
          .eq("edition_id", account.edition_id)
          .order("login_name");

        const { data: participants, error: participantsError } =
          await adminClient
            .from("ss_participants")
            .select("id, account_id, display_name, participant_type, excluded_from_draw")
            .eq("edition_id", account.edition_id)
            .order("display_name");

        const assignmentsCount =
          (await loadAssignmentMap(account.edition_id)).size;

        const { data: restrictionRows } = await adminClient
          .from("ss_draw_restrictions")
          .select("id, participant_a, participant_b")
          .eq("edition_id", account.edition_id);

        const nameOf = new Map(
          (participants ?? []).map(p => [p.id, p.display_name]),
        );

        const { data: editionRow } = await adminClient
          .from("ss_editions")
          .select("draw_date, registration_deadline")
          .eq("id", account.edition_id)
          .maybeSingle();

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
          draw_date: editionRow?.draw_date ?? null,
          fallback_draw_date: editionRow?.registration_deadline ?? null,
          restrictions: (restrictionRows ?? []).map(row => ({
            id: row.id,
            a_id: row.participant_a,
            b_id: row.participant_b,
            a_name: nameOf.get(row.participant_a) ?? "?",
            b_name: nameOf.get(row.participant_b) ?? "?",
          })),
          users: (accounts ?? []).map(item => ({
            ...item,
            participants: (participants ?? [])
              .filter(p => p.account_id === item.id)
              .map(p => ({
                id: p.id,
                display_name: p.display_name,
                participant_type: p.participant_type,
                excluded_from_draw: p.excluded_from_draw === true,
              })),
          })),
        });
      }

      // AGGIUNTA MANUALE DI UN UTENTE
      if (action === "admin_create_user") {
        if (await isDrawDone(account.edition_id)) {
          return response({ error: "L'estrazione è già stata fatta: per aggiungere o togliere persone resetta prima l'estrazione." }, 409);
        }

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

        if (!LOGIN_NAME_PATTERN.test(adultName.trim())) {
          return response({ error: LOGIN_NAME_ERROR }, 400);
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

        await logActivity(
          account.edition_id,
          "admin_create",
          adultName.trim(),
          `creato da ${account.login_name}`,
        );

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
          .update({
            must_reset_password: true,
            password_reset_requested_at: null,
          })
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

        await logActivity(
          account.edition_id,
          "password_reset",
          target.login_name,
          `reset da ${account.login_name}`,
        );

        return response({
          success: true,
          login_name: target.login_name,
          temp_password: tempPassword,
        });
      }

      // IGNORA UNA RICHIESTA DI RESET (es. la persona si è ricordata la password)
      if (action === "admin_dismiss_reset_request") {
        const targetId = body.account_id;

        if (!validText(targetId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        const { error: dismissError } = await adminClient
          .from("ss_accounts")
          .update({ password_reset_requested_at: null })
          .eq("id", targetId)
          .eq("edition_id", account.edition_id);

        if (dismissError) {
          console.error("Admin dismiss reset request:", dismissError.message);
          return response({ error: "Non è stato possibile ignorare la richiesta." }, 500);
        }

        return response({ success: true });
      }

      // WISHLIST DI UN QUALSIASI PARTECIPANTE (per correggerla)
      if (action === "admin_get_wishlist") {
        const participantId = body.participant_id;

        if (!validText(participantId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        const { data: participant, error: participantError } =
          await adminClient
            .from("ss_participants")
            .select("id, display_name")
            .eq("id", participantId)
            .eq("edition_id", account.edition_id)
            .maybeSingle();

        if (participantError || !participant) {
          return response({ error: "Partecipante non trovato." }, 400);
        }

        const { data: saved, error: savedError } = await adminClient
          .from("ss_wishlists")
          .select("ciphertext, nonce")
          .eq("participant_id", participant.id)
          .maybeSingle();

        if (savedError) {
          console.error("Admin get wishlist:", savedError.message);
          return response({ error: "Errore nel recupero della wishlist." }, 500);
        }

        return response({
          success: true,
          participant_id: participant.id,
          display_name: participant.display_name,
          gifts: saved ? await decryptWishlist(saved.ciphertext, saved.nonce) : [],
        });
      }

      // SALVATAGGIO DELLA WISHLIST DI UN PARTECIPANTE (senza limite di scadenza)
      if (action === "admin_save_wishlist") {
        const participantId = body.participant_id;
        const gifts = body.gifts;

        const giftsError = validateGifts(gifts);

        if (!validText(participantId) || giftsError) {
          return response({
            error: giftsError ?? "Richiesta non valida.",
          }, 400);
        }

        const { data: participant, error: participantError } =
          await adminClient
            .from("ss_participants")
            .select("id")
            .eq("id", participantId)
            .eq("edition_id", account.edition_id)
            .maybeSingle();

        if (participantError || !participant) {
          return response({ error: "Partecipante non trovato." }, 400);
        }

        const encrypted = await encryptWishlist(cleanGifts(gifts));

        const { error: saveError } = await adminClient
          .from("ss_wishlists")
          .upsert({
            participant_id: participant.id,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            key_version: encrypted.key_version,
            updated_at: new Date().toISOString(),
          }, { onConflict: "participant_id" });

        if (saveError) {
          console.error("Admin wishlist save:", saveError.message);
          return response({ error: "Non è stato possibile salvare la wishlist." }, 500);
        }

        return response({ success: true, message: "Wishlist salvata." });
      }

      // ELIMINAZIONE DI UN SINGOLO FIGLIO (di qualsiasi utente)
      if (action === "admin_delete_participant") {
        const participantId = body.participant_id;

        if (await isDrawDone(account.edition_id)) {
          return response({ error: "L'estrazione è già stata fatta: per aggiungere o togliere persone resetta prima l'estrazione." }, 409);
        }

        if (!validText(participantId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        const { data: target, error: targetError } = await adminClient
          .from("ss_participants")
          .select("id, display_name, participant_type")
          .eq("id", participantId)
          .eq("edition_id", account.edition_id)
          .maybeSingle();

        if (targetError || !target) {
          return response({ error: "Partecipante non trovato." }, 400);
        }

        if (target.participant_type !== "minor") {
          return response({
            error: "Si possono eliminare solo i figli. Per un adulto elimina l'intero utente.",
          }, 400);
        }

        const removed = await removeParticipants([target.id], account.edition_id);
        if (removed.error) return response({ error: removed.error }, 500);

        await logActivity(
          account.edition_id,
          "child_remove",
          null,
          `${target.display_name} eliminato da ${account.login_name}`,
        );

        return response({
          success: true,
          message: `${target.display_name} è stato eliminato.`,
          draw_affected: removed.drawAffected,
        });
      }

      // PARTECIPA / NON PARTECIPA ALL'ESTRAZIONE (es. animali di casa)
      if (action === "admin_set_excluded") {
        const participantId = body.participant_id;
        const excluded = body.excluded;

        if (!validText(participantId) || typeof excluded !== "boolean") {
          return response({ error: "Richiesta non valida." }, 400);
        }

        if (await isDrawDone(account.edition_id)) {
          return response({
            error: "L'estrazione è già stata fatta: resettala prima di cambiare chi partecipa.",
          }, 409);
        }

        const { data: updated, error: excludeError } = await adminClient
          .from("ss_participants")
          .update({ excluded_from_draw: excluded })
          .eq("id", participantId)
          .eq("edition_id", account.edition_id)
          .select("id");

        if (excludeError) {
          console.error("Admin set excluded:", excludeError.message);
          return response({ error: "Non è stato possibile aggiornare il partecipante." }, 500);
        }

        if (!updated?.length) {
          return response({ error: "Partecipante non trovato." }, 400);
        }

        return response({ success: true });
      }

      // ELIMINAZIONE DI UN UTENTE (con i suoi partecipanti e dati collegati)
      if (action === "admin_delete_user") {
        const targetId = body.account_id;

        if (await isDrawDone(account.edition_id)) {
          return response({ error: "L'estrazione è già stata fatta: per aggiungere o togliere persone resetta prima l'estrazione." }, 409);
        }

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

        const deleted = await deleteAccountCascade(target, account.edition_id);

        if (deleted.error) {
          return response({ error: deleted.error }, 500);
        }

        await logActivity(
          account.edition_id,
          "delete",
          target.login_name,
          `eliminato da ${account.login_name}`,
        );

        return response({
          success: true,
          message: `Utente "${target.login_name}" eliminato.`,
          draw_affected: deleted.drawAffected,
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

        await logActivity(account.edition_id, "draw_reset", account.login_name);

        return response({
          success: true,
          message: "Estrazione resettata: assegnazioni e regali scelti sono stati cancellati.",
        });
      }

      // REGISTRO DELLE ATTIVITÀ (le più recenti per prime)
      if (action === "admin_activity_log") {
        const requested = Number(body.limit);
        const limit = Number.isInteger(requested) && requested > 0
          ? Math.min(requested, 500)
          : 200;

        const { data: entries, error: logError } = await adminClient
          .from("ss_activity_log")
          .select("id, created_at, event, account_name, details")
          .eq("edition_id", account.edition_id)
          .order("created_at", { ascending: false })
          .limit(limit);

        if (logError) {
          console.error("Admin activity log:", logError.message);
          return response({
            error: "Non è stato possibile leggere il registro. Hai eseguito la migrazione SQL?",
          }, 500);
        }

        return response({ success: true, entries: entries ?? [] });
      }

      // DIVIETI: due persone che non possono pescarsi (in nessuna direzione)
      if (action === "admin_add_restriction") {
        const a = body.participant_a;
        const b = body.participant_b;

        if (!validText(a) || !validText(b) || a === b) {
          return response({ error: "Scegli due persone diverse." }, 400);
        }

        const { data: pair, error: pairError } = await adminClient
          .from("ss_participants")
          .select("id, account_id")
          .eq("edition_id", account.edition_id)
          .in("id", [a, b]);

        if (pairError || pair?.length !== 2) {
          return response({ error: "Partecipanti non trovati." }, 400);
        }

        if (pair[0].account_id === pair[1].account_id) {
          return response({
            error: "Sono della stessa famiglia: non possono già pescarsi.",
          }, 400);
        }

        const { data: existingRows, error: existingError } = await adminClient
          .from("ss_draw_restrictions")
          .select("participant_a, participant_b")
          .eq("edition_id", account.edition_id);

        if (existingError) {
          console.error("Add restriction lookup:", existingError.message);
          return response({
            error: "Non è stato possibile leggere i divieti. Hai eseguito la migrazione SQL?",
          }, 500);
        }

        if ((existingRows ?? []).some(row => pairKey(row.participant_a, row.participant_b) === pairKey(a, b))) {
          return response({ error: "Questo divieto esiste già." }, 409);
        }

        const { error: insertError } = await adminClient
          .from("ss_draw_restrictions")
          .insert({ edition_id: account.edition_id, participant_a: a, participant_b: b });

        if (insertError) {
          console.error("Add restriction:", insertError.message);
          return response({ error: "Non è stato possibile salvare il divieto." }, 500);
        }

        return response({ success: true });
      }

      if (action === "admin_remove_restriction") {
        const restrictionId = body.restriction_id;

        if (!validText(restrictionId)) {
          return response({ error: "Richiesta non valida." }, 400);
        }

        const { error: removeError } = await adminClient
          .from("ss_draw_restrictions")
          .delete()
          .eq("id", restrictionId)
          .eq("edition_id", account.edition_id);

        if (removeError) {
          console.error("Remove restriction:", removeError.message);
          return response({ error: "Non è stato possibile togliere il divieto." }, 500);
        }

        return response({ success: true });
      }

      // DATA DELL'ESTRAZIONE (per il countdown)
      if (action === "admin_set_draw_date") {
        const raw = body.draw_date;
        let value: string | null = null;

        if (raw !== null && raw !== "") {
          const parsed = typeof raw === "string" ? new Date(raw) : null;
          if (!parsed || Number.isNaN(parsed.getTime())) {
            return response({ error: "Data non valida." }, 400);
          }
          value = parsed.toISOString();
        }

        const { error: dateError } = await adminClient
          .from("ss_editions")
          .update({ draw_date: value })
          .eq("id", account.edition_id);

        if (dateError) {
          console.error("Admin set draw date:", dateError.message);
          return response({ error: "Non è stato possibile salvare la data." }, 500);
        }

        return response({ success: true, message: "Data dell'estrazione salvata." });
      }

      // ESTRAZIONE DEL SECRET SANTA
      if (action === "admin_draw") {
        const { data: everyone, error: everyoneError } = await adminClient
          .from("ss_participants")
          .select("id, account_id, excluded_from_draw")
          .eq("edition_id", account.edition_id);

        if (everyoneError) {
          return response({ error: "Errore nel recupero partecipanti." }, 500);
        }

        const allIds = (everyone ?? []).map(person => person.id);
        // chi è escluso (es. gli animali di casa) non pesca e non viene pescato
        const people = (everyone ?? []).filter(person => !person.excluded_from_draw);

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

        // Divieti decisi dall'admin (es. persone che non si parlano)
        const { data: restrictionRows, error: restrictionsError } =
          await adminClient
            .from("ss_draw_restrictions")
            .select("participant_a, participant_b")
            .eq("edition_id", account.edition_id);

        if (restrictionsError) {
          console.error("Draw restrictions:", restrictionsError.message);
          return response({
            error: "Non è stato possibile leggere i divieti. Hai eseguito la migrazione SQL?",
          }, 500);
        }

        const forbidden = new Set(
          (restrictionRows ?? []).map(row =>
            pairKey(row.participant_a, row.participant_b)
          ),
        );

        // Nessuno pesca sé stesso, un familiare o una persona vietata
        const receivers = findAssignment(people, forbidden);

        if (!receivers) {
          return response({
            error: "Non è possibile fare un'estrazione valida con le famiglie e i divieti attuali. Prova a togliere qualche divieto.",
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
          .in("participant_id", allIds);

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

        await logActivity(
          account.edition_id,
          "draw",
          account.login_name,
          `${rows.length} partecipanti`,
        );

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

      // per l'admin: quante persone hanno chiesto il reset della password
      let pendingResetCount = 0;

      if (account.role === "admin") {
        const { count } = await adminClient
          .from("ss_accounts")
          .select("id", { count: "exact", head: true })
          .eq("edition_id", account.edition_id)
          .not("password_reset_requested_at", "is", null);

        pendingResetCount = count ?? 0;
      }

      return response({
        success: true,
        account: {
          id: account.id,
          login_name: account.login_name,
          role: account.role,
          must_reset_password: account.must_reset_password,
        },
        pending_reset_count: pendingResetCount,
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
