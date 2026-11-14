
import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get(
  "SUPABASE_SERVICE_ROLE_KEY",
)!;

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

    const authorization = req.headers.get("Authorization");

    if (!authorization?.startsWith("Bearer ")) {
      return response({ error: "Autenticazione richiesta" }, 401);
    }

    const token = authorization.slice(7);

    const {
      data: { user },
      error: authError,
    } = await authClient.auth.getUser(token);

    if (authError || !user) {
      return response({ error: "Sessione non valida" }, 401);
    }

    if (action === "whoami") {
      const { data: account, error: accountError } =
        await adminClient
          .from("ss_accounts")
          .select(
            "id, edition_id, login_name, role, must_reset_password",
          )
          .eq("auth_user_id", user.id)
          .maybeSingle();

      if (accountError) {
        console.error("Account lookup:", accountError.message);
        return response({ error: "Errore nel recupero account" }, 500);
      }

      if (!account) {
        return response({ error: "Account non trovato" }, 404);
      }

      const { data: edition, error: editionError } =
        await adminClient
          .from("ss_editions")
          .select("id, year, status, registration_deadline, wishlist_deadline")
          .eq("id", account.edition_id)
          .maybeSingle();

      if (editionError) {
        console.error("Edition lookup:", editionError.message);
        return response({ error: "Errore nel recupero edizione" }, 500);
      }

      const { data: participants, error: participantsError } =
        await adminClient
          .from("ss_participants")
          .select("id, display_name, participant_type, must_reset_password")
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

    return response({ error: "Azione non ancora implementata" }, 400);
  } catch (error) {
    console.error("Function error:", error);
    return response({ error: "Richiesta non valida" }, 400);
  }
});
