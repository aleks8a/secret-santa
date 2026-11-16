-- Richieste di reset password: l'utente che ha dimenticato la password
-- valorizza questa colonna, l'admin la vede e la azzera con il reset.
alter table public.ss_accounts
  add column if not exists password_reset_requested_at timestamptz;
