import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
create table if not exists users(id text primary key, username text not null collate nocase unique, display_name text not null, pass_hash text not null, read_receipts integer not null default 1, created_at integer not null);
create table if not exists sessions(token_hash text primary key, user_id text not null references users(id) on delete cascade, expires_at integer not null);
create table if not exists conversations(id text primary key, kind text not null check(kind in('direct','group','saved')), title text, direct_key text unique, created_by text, created_at integer not null);
create table if not exists members(conversation_id text not null references conversations(id) on delete cascade, user_id text not null references users(id) on delete cascade, role text not null default 'member' check(role in('owner','admin','member')), last_read_seq integer not null default 0, muted_until integer, archived integer not null default 0, pinned integer not null default 0, favorite integer not null default 0, primary key(conversation_id,user_id));
create index if not exists members_user on members(user_id);
create table if not exists messages(seq integer primary key autoincrement, id text not null unique, conversation_id text not null references conversations(id) on delete cascade, sender_id text not null references users(id) on delete cascade, client_id text not null, body text not null, reply_to text, created_at integer not null, edited_at integer, deleted_at integer, unique(conversation_id,sender_id,client_id));
create index if not exists msg_conv on messages(conversation_id,seq);
create table if not exists reactions(message_id text not null references messages(id) on delete cascade, user_id text not null references users(id) on delete cascade, emoji text not null, primary key(message_id,user_id,emoji));
create table if not exists blocks(blocker_id text not null references users(id) on delete cascade, blocked_id text not null references users(id) on delete cascade, primary key(blocker_id,blocked_id));
create table if not exists reports(id text primary key, reporter_id text not null references users(id) on delete cascade, target_user text, target_message text, reason text not null, status text not null default 'open', created_at integer not null);
create table if not exists folders(id text primary key, user_id text not null references users(id) on delete cascade, name text not null, icon text not null default 'folder', position integer not null default 0);
create table if not exists folder_rules(folder_id text not null references folders(id) on delete cascade, rule text not null, mode text not null, primary key(folder_id,rule));
create table if not exists folder_chats(folder_id text not null references folders(id) on delete cascade, conversation_id text not null references conversations(id) on delete cascade, mode text not null, primary key(folder_id,conversation_id));
create table if not exists mod_log(id integer primary key autoincrement, conversation_id text not null, actor_id text not null, action text not null, target_user text, at integer not null);
`;

export function openDb(file = ':memory:') {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');
  db.exec(SCHEMA);
  return db;
}
