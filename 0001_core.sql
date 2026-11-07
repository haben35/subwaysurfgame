-- ChatSphere migration 0001: core schema, Row Level Security, RPCs, folder engine.
-- Target: Supabase (Postgres 15+). NOT yet run against a database: test before use.

-- ========== PROFILES (public) and SETTINGS (private) ==========
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[a-z0-9_]{3,32}$'),
  display_name text not null default '' check (char_length(display_name) <= 64),
  bio text not null default '' check (char_length(bio) <= 300),
  avatar_path text,
  last_seen_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index profiles_username_key on public.profiles (lower(username));

create table public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  show_last_seen text not null default 'contacts' check (show_last_seen in ('everyone','contacts','nobody')),
  read_receipts boolean not null default true,
  notif_preview boolean not null default true,
  quiet_from time, quiet_to time,
  updated_at timestamptz not null default now()
);

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, username, display_name)
  values (new.id, 'user_' || substr(replace(new.id::text,'-',''),1,10), coalesce(split_part(new.email,'@',1),''));
  insert into user_settings (user_id) values (new.id);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ========== CONVERSATIONS ==========
create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('direct','group','saved')),
  title text check (char_length(title) <= 100),
  direct_key text unique,               -- 'minUuid:maxUuid' for direct, 'saved:uid' for saved
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','moderator','member')),
  joined_at timestamptz not null default now(),
  last_read_at timestamptz,
  muted_until timestamptz,
  archived boolean not null default false,
  pinned_at timestamptz,
  favorite boolean not null default false,
  label text check (char_length(label) <= 32),
  primary key (conversation_id, user_id)
);
create index cm_user_idx on public.conversation_members (user_id);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  client_id uuid not null,              -- client-generated id: duplicate-send protection
  body text not null check (char_length(body) <= 4000),
  reply_to uuid,
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_at timestamptz,
  unique (conversation_id, sender_id, client_id),
  unique (id, conversation_id),
  foreign key (reply_to, conversation_id) references public.messages (id, conversation_id) on delete set null (reply_to)
);
create index messages_conv_time_idx on public.messages (conversation_id, created_at desc, id desc);

create table public.message_receipts (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  delivered_at timestamptz, read_at timestamptz,
  primary key (message_id, user_id)
);
create table public.message_reactions (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null check (char_length(emoji) between 1 and 16),
  primary key (message_id, user_id, emoji)
);
create table public.user_blocks (
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id), check (blocker_id <> blocked_id)
);
create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete cascade,
  target_user uuid references auth.users(id) on delete set null,
  target_message uuid references public.messages(id) on delete set null,
  reason text not null check (char_length(reason) between 1 and 1000),
  status text not null default 'open' check (status in ('open','reviewing','actioned','dismissed')),
  created_at timestamptz not null default now(),
  check (target_user is not null or target_message is not null)
);

-- ========== FOLDERS ==========
create table public.folders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 32),
  icon text not null default 'folder',
  position int not null default 0,
  created_at timestamptz not null default now()
);
create index folders_user_idx on public.folders (user_id, position);
create table public.folder_rules (
  folder_id uuid not null references public.folders(id) on delete cascade,
  rule text not null check (rule in ('unread','muted','archived','group','direct','favorite')),
  mode text not null check (mode in ('include','exclude')),
  primary key (folder_id, rule)
);
create table public.folder_conversations (
  folder_id uuid not null references public.folders(id) on delete cascade,
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  mode text not null check (mode in ('include','exclude')),
  primary key (folder_id, conversation_id)
);

-- ========== HELPERS (security definer avoids RLS recursion) ==========
create function public.is_member(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from conversation_members where conversation_id = cid and user_id = auth.uid()) $$;

create function public.can_send(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select is_member(cid) and not exists (
    select 1 from conversations c join conversation_members o on o.conversation_id = c.id and o.user_id <> auth.uid()
    join user_blocks b on (b.blocker_id = o.user_id and b.blocked_id = auth.uid()) or (b.blocker_id = auth.uid() and b.blocked_id = o.user_id)
    where c.id = cid and c.kind = 'direct') $$;

create function public.unread_count(cid uuid) returns bigint
language sql stable set search_path = public as $$
  select count(*) from messages m
  where m.conversation_id = cid and m.sender_id <> auth.uid() and m.deleted_at is null
    and m.created_at > coalesce((select last_read_at from conversation_members where conversation_id = cid and user_id = auth.uid()), '-infinity') $$;

-- ========== FOLDER ENGINE ==========
-- Rule resolution (highest priority first):
--  1. explicit per-chat EXCLUDE            -> not in folder
--  2. explicit per-chat INCLUDE            -> in folder
--  3. any matching EXCLUDE rule            -> not in folder
--  4. any matching INCLUDE rule            -> in folder
--  5. otherwise                            -> not in folder (a folder with no includes is empty)
create function public.chat_in_folder(fid uuid, cid uuid) returns boolean
language plpgsql stable set search_path = public as $$
declare m record; r record; hit boolean; inc boolean := false;
begin
  if not exists (select 1 from folders where id = fid and user_id = auth.uid()) then return false; end if;
  select cm.muted_until, cm.archived, cm.favorite, c.kind into m
    from conversation_members cm join conversations c on c.id = cm.conversation_id
    where cm.conversation_id = cid and cm.user_id = auth.uid();
  if not found then return false; end if;
  if exists (select 1 from folder_conversations where folder_id = fid and conversation_id = cid and mode = 'exclude') then return false; end if;
  if exists (select 1 from folder_conversations where folder_id = fid and conversation_id = cid and mode = 'include') then return true; end if;
  for r in select rule, mode from folder_rules where folder_id = fid loop
    hit := case r.rule
      when 'unread'   then unread_count(cid) > 0
      when 'muted'    then m.muted_until is not null and m.muted_until > now()
      when 'archived' then m.archived
      when 'group'    then m.kind = 'group'
      when 'direct'   then m.kind = 'direct'
      when 'favorite' then m.favorite
      else false end;
    if r.mode = 'exclude' and hit then return false; end if;
    if r.mode = 'include' and hit then inc := true; end if;
  end loop;
  return inc;
end $$;

create function public.folder_chats(fid uuid) returns setof uuid
language sql stable set search_path = public as $$
  select conversation_id from conversation_members
  where user_id = auth.uid() and chat_in_folder(fid, conversation_id) $$;

create function public.folder_unread(fid uuid) returns bigint
language sql stable set search_path = public as $$
  select coalesce(sum(unread_count(c)), 0) from folder_chats(fid) c $$;

-- ========== RPCs (the only way to create conversations or delete for everyone) ==========
create function public.start_direct(other uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); key text; cid uuid;
begin
  if me is null then raise exception 'not authenticated'; end if;
  if other = me or not exists (select 1 from profiles where id = other) then raise exception 'invalid user'; end if;
  if exists (select 1 from user_blocks where (blocker_id = other and blocked_id = me) or (blocker_id = me and blocked_id = other)) then raise exception 'blocked'; end if;
  key := least(me::text, other::text) || ':' || greatest(me::text, other::text);
  select id into cid from conversations where direct_key = key;
  if cid is null then
    insert into conversations (kind, direct_key, created_by) values ('direct', key, me)
      on conflict (direct_key) do nothing returning id into cid;
    if cid is null then select id into cid from conversations where direct_key = key; end if;
    insert into conversation_members (conversation_id, user_id) values (cid, me), (cid, other) on conflict do nothing;
  end if;
  return cid;
end $$;

create function public.ensure_saved() returns uuid
language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); cid uuid;
begin
  if me is null then raise exception 'not authenticated'; end if;
  select id into cid from conversations where direct_key = 'saved:' || me;
  if cid is null then
    insert into conversations (kind, title, direct_key, created_by) values ('saved','Saved messages','saved:' || me, me) returning id into cid;
    insert into conversation_members (conversation_id, user_id, role) values (cid, me, 'owner');
  end if;
  return cid;
end $$;

create function public.delete_message(mid uuid) returns void
language plpgsql security definer set search_path = public as $$
declare m messages; role_ text;
begin
  select * into m from messages where id = mid;
  if not found then return; end if;
  select role into role_ from conversation_members where conversation_id = m.conversation_id and user_id = auth.uid();
  if role_ is null then raise exception 'forbidden'; end if;
  if m.sender_id <> auth.uid() and role_ not in ('owner','admin','moderator') then raise exception 'forbidden'; end if;
  update messages set body = '', deleted_at = now() where id = mid;
end $$;

create function public.mark_read(cid uuid) returns void
language plpgsql security definer set search_path = public as $$
declare prev timestamptz;
begin
  if not is_member(cid) then raise exception 'forbidden'; end if;
  select last_read_at into prev from conversation_members where conversation_id = cid and user_id = auth.uid();
  update conversation_members set last_read_at = now() where conversation_id = cid and user_id = auth.uid();
  insert into message_receipts (message_id, user_id, read_at)
    select m.id, auth.uid(), now() from messages m
    where m.conversation_id = cid and m.sender_id <> auth.uid() and m.created_at > coalesce(prev, '-infinity')
      and exists (select 1 from user_settings s where s.user_id = auth.uid() and s.read_receipts)
  on conflict (message_id, user_id) do update set read_at = coalesce(message_receipts.read_at, excluded.read_at);
end $$;

create function public.touch_edit() returns trigger language plpgsql as $$
begin
  if new.body is distinct from old.body then new.edited_at := now(); end if;
  return new;
end $$;
create trigger messages_touch_edit before update on public.messages for each row execute function public.touch_edit();

-- ========== ROW LEVEL SECURITY ==========
alter table public.profiles enable row level security;
alter table public.user_settings enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.message_receipts enable row level security;
alter table public.message_reactions enable row level security;
alter table public.user_blocks enable row level security;
alter table public.reports enable row level security;
alter table public.folders enable row level security;
alter table public.folder_rules enable row level security;
alter table public.folder_conversations enable row level security;

create policy profiles_read on public.profiles for select to authenticated using (true);
create policy profiles_update on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy settings_own on public.user_settings for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy conv_read on public.conversations for select to authenticated using (is_member(id));
create policy cm_read on public.conversation_members for select to authenticated using (user_id = auth.uid() or is_member(conversation_id));
create policy cm_update_own on public.conversation_members for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy msg_read on public.messages for select to authenticated using (is_member(conversation_id));
create policy msg_insert on public.messages for insert to authenticated with check (sender_id = auth.uid() and can_send(conversation_id));
create policy msg_edit on public.messages for update to authenticated using (sender_id = auth.uid() and deleted_at is null) with check (sender_id = auth.uid());

create policy rcpt_read on public.message_receipts for select to authenticated
  using (exists (select 1 from messages m where m.id = message_id and is_member(m.conversation_id)));
create policy react_read on public.message_reactions for select to authenticated
  using (exists (select 1 from messages m where m.id = message_id and is_member(m.conversation_id)));
create policy react_add on public.message_reactions for insert to authenticated
  with check (user_id = auth.uid() and exists (select 1 from messages m where m.id = message_id and is_member(m.conversation_id)));
create policy react_del on public.message_reactions for delete to authenticated using (user_id = auth.uid());

create policy blocks_own on public.user_blocks for all to authenticated using (blocker_id = auth.uid()) with check (blocker_id = auth.uid());
create policy reports_add on public.reports for insert to authenticated with check (reporter_id = auth.uid());
create policy reports_read on public.reports for select to authenticated using (reporter_id = auth.uid());

create policy folders_own on public.folders for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy frules_own on public.folder_rules for all to authenticated
  using (exists (select 1 from folders f where f.id = folder_id and f.user_id = auth.uid()))
  with check (exists (select 1 from folders f where f.id = folder_id and f.user_id = auth.uid()));
create policy fconv_own on public.folder_conversations for all to authenticated
  using (exists (select 1 from folders f where f.id = folder_id and f.user_id = auth.uid()))
  with check (exists (select 1 from folders f where f.id = folder_id and f.user_id = auth.uid()) and is_member(conversation_id));

-- ========== COLUMN-LEVEL GRANTS: clients may not change roles, senders or timestamps ==========
revoke all on all tables in schema public from anon;
revoke insert, update, delete on public.conversations, public.conversation_members, public.message_receipts from authenticated;
revoke update on public.messages from authenticated;
grant update (body) on public.messages to authenticated;
grant update (last_read_at, muted_until, archived, pinned_at, favorite, label) on public.conversation_members to authenticated;
grant update (username, display_name, bio, avatar_path) on public.profiles to authenticated;
revoke update on public.profiles from authenticated; grant update (username, display_name, bio, avatar_path) on public.profiles to authenticated;
revoke execute on all functions in schema public from anon;

-- ========== REALTIME (Supabase only) ==========
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.messages, public.message_reactions, public.conversation_members;
  end if;
end $$;
