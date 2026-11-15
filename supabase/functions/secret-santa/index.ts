
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
          participant_type: index === 0 ? "adult" : "child",
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

      const participantIds = (participants ?? []).map(item => item.id);
      const { data: wishlists, error: wishlistsError } = participantIds.length
        ? await adminClient
            .from("ss_wishlists")
            .select("participant_id, ciphertext, nonce")
            .in("participant_id", participantIds)
        : { data: [], error: null };

      if (wishlistsError) {
        console.error("Public wishlists lookup:", wishlistsError.message);
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
