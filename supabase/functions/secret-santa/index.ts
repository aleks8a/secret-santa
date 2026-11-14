
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
        newPassword.length < 12 ||
        newPassword.length > 128
      ) {
        return response({
          error: "La nuova password deve avere almeno 12 caratteri",
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
          .select(
            "id, display_name, participant_type, must_reset_password",
          )
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
