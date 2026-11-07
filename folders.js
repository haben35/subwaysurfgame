// Folder rule engine. Resolution order (highest priority first):
//  1. explicit per-chat EXCLUDE  -> not in folder
//  2. explicit per-chat INCLUDE  -> in folder
//  3. any matching EXCLUDE rule  -> not in folder
//  4. any matching INCLUDE rule  -> in folder
//  5. otherwise                  -> not in folder
export const RULES = ['unread', 'muted', 'archived', 'group', 'direct', 'favorite'];
export const MODES = ['include', 'exclude'];

export function chatsFor(db, uid) {
  return db.prepare(`select c.id, c.kind, m.muted_until, m.archived, m.pinned, m.favorite, m.last_read_seq,
    (select count(*) from messages x where x.conversation_id=c.id and x.seq>m.last_read_seq and x.sender_id<>? and x.deleted_at is null) as unread
    from members m join conversations c on c.id=m.conversation_id where m.user_id=?`).all(uid, uid);
}

export function matches(chat, rules, explicit, now = Date.now()) {
  const ex = explicit.get(chat.id);
  if (ex === 'exclude') return false;
  if (ex === 'include') return true;
  const state = {
    unread: chat.unread > 0, muted: (chat.muted_until || 0) > now, archived: !!chat.archived,
    group: chat.kind === 'group', direct: chat.kind === 'direct', favorite: !!chat.favorite,
  };
  let inc = false;
  for (const r of rules) {
    const hit = !!state[r.rule];
    if (r.mode === 'exclude' && hit) return false;
    if (r.mode === 'include' && hit) inc = true;
  }
  return inc;
}

export function folderChats(db, uid, folderId) {
  const rules = db.prepare('select rule, mode from folder_rules where folder_id=?').all(folderId);
  const explicit = new Map(db.prepare('select conversation_id, mode from folder_chats where folder_id=?').all(folderId).map(r => [r.conversation_id, r.mode]));
  const chats = chatsFor(db, uid).filter(c => matches(c, rules, explicit));
  return { chats: chats.map(c => c.id), unread: chats.reduce((n, c) => n + c.unread, 0) };
}
