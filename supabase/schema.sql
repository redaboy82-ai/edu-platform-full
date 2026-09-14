-- Durable storage for the Edu Platform.
-- Run this once in Supabase SQL Editor.
-- IMPORTANT: the server should use SUPABASE_SECRET_KEY (sb_secret_...) for this table.
-- Do NOT expose a secret key in the browser or commit it to GitHub.

create table if not exists public.platform_state (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

-- Keep the table private. The Node server accesses it with the Supabase secret key.
alter table public.platform_state enable row level security;

revoke all on table public.platform_state from anon, authenticated;

create index if not exists platform_state_updated_at_idx
  on public.platform_state (updated_at desc);
