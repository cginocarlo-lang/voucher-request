create table users (
  username text primary key, salt text not null, password_hash text not null,
  active boolean not null default true, role text not null default 'office',
  office text default '', name text default '', must_change boolean not null default false
);
create unique index users_lower_idx on users (lower(username));

create table sessions (token text primary key, username text not null, exp timestamptz not null);

create table obr (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  obr_no text default '', payee text default '', office text default '', address text default '',
  items jsonb not null default '[]', amount numeric(14,2) not null default 0,
  dv_no text default '', dv_date text default '', id_no text default '', dv_class text default '',
  owner text not null
);
create index obr_owner_idx on obr (owner);

create table account_codes (code text primary key, title text, budget numeric(16,2) default 0);
create table rc_codes (code text primary key, title text);
create table fpp_codes (code text primary key, title text);
create table dept_head (name text, title text);

-- The browser never talks to Supabase directly; only the server (service key) does.
alter table users enable row level security;
alter table sessions enable row level security;
alter table obr enable row level security;
alter table account_codes enable row level security;
alter table rc_codes enable row level security;
alter table fpp_codes enable row level security;
alter table dept_head enable row level security;
