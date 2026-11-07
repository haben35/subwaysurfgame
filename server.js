import http from 'node:http';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { openDb } from './db.js';
import { attachWs } from './ws.js';
import { folderChats, chatsFor, matches, RULES, MODES } from './folders.js';

const scrypt = promisify(crypto.scrypt);
export class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = m => new HttpError(400, m);
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const UUID = /^[0-9a-f-]{36}$/i;
const DAY = 864e5;

async function hashPw(pw) { const salt = crypto.randomBytes(16); const h = await scrypt(pw, salt, 64); return `${salt.toString('hex')}:${h.toString('hex')}`; }
async function checkPw(pw, stored) {
  const [s, h] = stored.split(':'); const d = await scrypt(pw, Buffer.from(s, 'hex'), 64); const hb = Buffer.from(h, 'hex');
  return hb.length === d.length && crypto.timingSafeEqual(hb, d);
}
function limiter(max, windowMs) {
  const hits = new Map();
  return key => { const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < windowMs); a.push(now); hits.set(key, a); return a.length <= max; };
}
const str = (v, min, max, name) => { if (typeof v !== 'string' || v.length < min || v.length > max) throw bad(`${name} must be ${min}-${max} characters`); return v; };

export function createApp({ dbFile = ':memory:', limit = 10, allowedOrigin = '' } = {}) {
  const db = openDb(dbFile);
  const hub = new Map();
  const authLimit = limiter(limit, 60000);
  const one = (sql, ...a) => db.prepare(sql).get(...a);
  const all = (sql, ...a) => db.prepare(sql).all(...a);
  const run = (sql, ...a) => db.prepare(sql).run(...a);
  const tx = fn => { db.exec('BEGIN'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  const dummyHash = hashPw('dummy-password-for-timing');

  const uidFromToken = t => { const s = one('select user_id from sessions where token_hash=? and expires_at>?', sha(t), Date.now()); return s ? s.user_id : null; };
  const member = (cid, uid) => { const m = UUID.test(cid) && one('select * from members where conversation_id=? and user_id=?', cid, uid); if (!m) throw new HttpError(404, 'not found'); return m; };
  const blocked = (a, b) => !!one('select 1 x from blocks where (blocker_id=? and blocked_id=?) or (blocker_id=? and blocked_id=?)', a, b, b, a);
  const peerOf = (cid, uid) => one('select user_id from members where conversation_id=? and user_id<>?', cid, uid)?.user_id;
  function publish(cid, ev, exceptUid) {
    for (const { user_id } of all('select user_id from members where conversation_id=?', cid)) {
      if (user_id === exceptUid) continue;
      for (const c of hub.get(user_id) || []) c.send(ev);
    }
  }
  function view(m, uid) {
    const rx = all('select emoji, count(*) n, coalesce(sum(user_id=?),0) mine from reactions where message_id=? group by emoji', uid || '', m.id);
    return { id: m.id, seq: m.seq, conversation_id: m.conversation_id, sender_id: m.sender_id, body: m.deleted_at ? '' : m.body, reply_to: m.reply_to, created_at: m.created_at, edited_at: m.edited_at, deleted: !!m.deleted_at, reactions: rx.map(r => ({ emoji: r.emoji, count: r.n, mine: !!r.mine })) };
  }
  const message = (id, uid) => {
    const m = UUID.test(id) && one('select * from messages where id=?', id);
    if (!m) throw new HttpError(404, 'not found');
    member(m.conversation_id, uid);
    return m;
  };
  async function session(uid) {
    const token = crypto.randomBytes(32).toString('base64url');
    run('insert into sessions(token_hash,user_id,expires_at) values(?,?,?)', sha(token), uid, Date.now() + 30 * DAY);
    return token;
  }

  const routes = [];
  const route = (method, path, auth, fn) => routes.push({ method, re: new RegExp(`^${path}$`), auth, fn });

  // ---------- auth ----------
  route('POST', '/api/register', false, async ({ body, ip }) => {
    if (!authLimit('reg:' + ip)) throw new HttpError(429, 'too many attempts');
    const username = str(body.username, 3, 32, 'username').toLowerCase();
    if (!/^[a-z0-9_]+$/.test(username)) throw bad('username may use letters, digits and underscores');
    str(body.password, 8, 128, 'password');
    const display = body.display_name == null ? username : str(body.display_name, 1, 64, 'display_name');
    if (one('select 1 x from users where username=?', username)) throw new HttpError(409, 'username taken');
    const id = crypto.randomUUID();
    run('insert into users(id,username,display_name,pass_hash,created_at) values(?,?,?,?,?)', id, username, display, await hashPw(body.password), Date.now());
    return [201, { token: await session(id), user: { id, username, display_name: display } }];
  });
  route('POST', '/api/login', false, async ({ body, ip }) => {
    if (!authLimit('login:' + ip)) throw new HttpError(429, 'too many attempts');
    const u = typeof body.username === 'string' ? one('select * from users where username=?', body.username.toLowerCase()) : null;
    const ok = await checkPw(String(body.password ?? ''), u ? u.pass_hash : await dummyHash);
    if (!u || !ok) throw new HttpError(401, 'invalid credentials');
    return { token: await session(u.id), user: { id: u.id, username: u.username, display_name: u.display_name } };
  });
  route('POST', '/api/logout', true, ({ token }) => { run('delete from sessions where token_hash=?', sha(token)); return { ok: true }; });
  route('POST', '/api/logout-others', true, ({ u, token }) => { run('delete from sessions where user_id=? and token_hash<>?', u.id, sha(token)); return { ok: true }; });
  route('GET', '/api/me', true, ({ u }) => ({ user: u }));
  route('PATCH', '/api/settings', true, ({ u, body }) => { if (typeof body.read_receipts !== 'boolean') throw bad('read_receipts must be boolean'); run('update users set read_receipts=? where id=?', +body.read_receipts, u.id); return { ok: true }; });
  route('DELETE', '/api/me', true, ({ u, body }) => {
    if (body.confirm !== u.username) throw bad('send {"confirm": "<your username>"} to delete the account');
    run('delete from users where id=?', u.id); return { ok: true };
  });

  // ---------- users, blocks, reports ----------
  route('GET', '/api/users', true, ({ u, query }) => {
    const q = str(query.get('q') || '', 2, 32, 'q').toLowerCase().replace(/[\\%_]/g, c => '\\' + c);
    return { users: all(`select id, username, display_name from users where username like ? escape '\\' and id<>? and id not in (select blocker_id from blocks where blocked_id=?) order by username limit 20`, q + '%', u.id, u.id) };
  });
  route('POST', '/api/blocks', true, ({ u, body }) => {
    if (!UUID.test(body.user_id || '') || body.user_id === u.id || !one('select 1 x from users where id=?', body.user_id)) throw bad('invalid user');
    run('insert or ignore into blocks values(?,?)', u.id, body.user_id); return { ok: true };
  });
  route('DELETE', '/api/blocks/([^/]+)', true, ({ u, params }) => { run('delete from blocks where blocker_id=? and blocked_id=?', u.id, params[0]); return { ok: true }; });
  route('POST', '/api/reports', true, ({ u, body }) => {
    str(body.reason, 1, 1000, 'reason');
    if (!body.user_id && !body.message_id) throw bad('user_id or message_id required');
    if (body.message_id) message(body.message_id, u.id);
    if (body.user_id && !one('select 1 x from users where id=?', body.user_id)) throw bad('invalid user');
    const id = crypto.randomUUID();
    run('insert into reports(id,reporter_id,target_user,target_message,reason,created_at) values(?,?,?,?,?,?)', id, u.id, body.user_id || null, body.message_id || null, body.reason, Date.now());
    return [201, { id }];
  });

  // ---------- chats ----------
  route('POST', '/api/chats/direct', true, ({ u, body }) => {
    const other = body.user_id;
    if (!UUID.test(other || '') || other === u.id || !one('select 1 x from users where id=?', other)) throw bad('invalid user');
    if (blocked(u.id, other)) throw new HttpError(403, 'blocked');
    const key = [u.id, other].sort().join(':');
    return tx(() => {
      let c = one('select id from conversations where direct_key=?', key);
      if (!c) {
        c = { id: crypto.randomUUID() };
        run("insert into conversations(id,kind,direct_key,created_by,created_at) values(?, 'direct', ?, ?, ?)", c.id, key, u.id, Date.now());
        run('insert into members(conversation_id,user_id) values(?,?),(?,?)', c.id, u.id, c.id, other);
      }
      return { id: c.id };
    });
  });
  route('POST', '/api/chats/saved', true, ({ u }) => tx(() => {
    const key = 'saved:' + u.id; let c = one('select id from conversations where direct_key=?', key);
    if (!c) { c = { id: crypto.randomUUID() }; run("insert into conversations(id,kind,title,direct_key,created_by,created_at) values(?, 'saved','Saved messages',?,?,?)", c.id, key, u.id, Date.now()); run("insert into members(conversation_id,user_id,role) values(?,?,'owner')", c.id, u.id); }
    return { id: c.id };
  }));
  route('GET', '/api/chats', true, ({ u, query }) => {
    let rows = chatsFor(db, u.id);
    const fid = query.get('folder_id');
    if (fid) {
      const f = UUID.test(fid) && one('select id from folders where id=? and user_id=?', fid, u.id);
      if (!f) throw new HttpError(404, 'not found');
      const rules = all('select rule, mode from folder_rules where folder_id=?', fid);
      const ex = new Map(all('select conversation_id, mode from folder_chats where folder_id=?', fid).map(r => [r.conversation_id, r.mode]));
      rows = rows.filter(c => matches(c, rules, ex));
    } else if (query.get('archived') !== '1') rows = rows.filter(c => !c.archived);
    const out = rows.map(c => {
      const last = one('select sender_id, body, created_at, deleted_at from messages where conversation_id=? order by seq desc limit 1', c.id);
      const info = one('select title, kind from conversations where id=?', c.id);
      let title = info.title, peer = null;
      if (c.kind === 'direct') { peer = peerOf(c.id, u.id); title = one('select display_name from users where id=?', peer)?.display_name; }
      return { id: c.id, kind: c.kind, title, peer_id: peer, unread: c.unread, muted_until: c.muted_until, archived: !!c.archived, pinned: !!c.pinned, favorite: !!c.favorite, last_message: last ? { sender_id: last.sender_id, body: last.deleted_at ? '' : last.body, created_at: last.created_at } : null };
    });
    out.sort((a, b) => (b.pinned - a.pinned) || ((b.last_message?.created_at || 0) - (a.last_message?.created_at || 0)));
    return { chats: out };
  });
  route('PATCH', '/api/chats/([^/]+)/prefs', true, ({ u, params, body }) => {
    member(params[0], u.id);
    for (const k of ['archived', 'pinned', 'favorite']) if (k in body) { if (typeof body[k] !== 'boolean') throw bad(k + ' must be boolean'); run(`update members set ${k}=? where conversation_id=? and user_id=?`, +body[k], params[0], u.id); }
    if ('muted_until' in body) { if (body.muted_until !== null && !Number.isInteger(body.muted_until)) throw bad('muted_until must be integer or null'); run('update members set muted_until=? where conversation_id=? and user_id=?', body.muted_until, params[0], u.id); }
    return { ok: true };
  });
  route('POST', '/api/chats/([^/]+)/read', true, ({ u, params }) => {
    member(params[0], u.id);
    const seq = one('select coalesce(max(seq),0) s from messages where conversation_id=?', params[0]).s;
    run('update members set last_read_seq=? where conversation_id=? and user_id=?', seq, params[0], u.id);
    if (one('select read_receipts r from users where id=?', u.id).r) publish(params[0], { type: 'read', conversation_id: params[0], user_id: u.id, seq }, u.id);
    return { ok: true, seq };
  });
  route('GET', '/api/chats/([^/]+)/messages', true, ({ u, params, query }) => {
    member(params[0], u.id);
    const lim = Math.min(100, Math.max(1, Number(query.get('limit')) || 50));
    const before = Number(query.get('before')) || null;
    const rows = all('select * from messages where conversation_id=? and (? is null or seq<?) order by seq desc limit ?', params[0], before, before, lim).reverse();
    return { messages: rows.map(m => view(m, u.id)), next_before: rows.length === lim ? rows[0].seq : null };
  });
  route('POST', '/api/chats/([^/]+)/messages', true, ({ u, params, body }) => {
    const cid = params[0], conv = (member(cid, u.id), one('select kind from conversations where id=?', cid));
    if (!UUID.test(body.client_id || '')) throw bad('client_id must be a UUID');
    const text = str(body.body, 1, 4000, 'body');
    if (conv.kind === 'direct' && blocked(u.id, peerOf(cid, u.id))) throw new HttpError(403, 'blocked');
    if (body.reply_to != null && !one('select 1 x from messages where id=? and conversation_id=?', String(body.reply_to), cid)) throw bad('reply_to not in this chat');
    const id = crypto.randomUUID();
    const r = run('insert into messages(id,conversation_id,sender_id,client_id,body,reply_to,created_at) values(?,?,?,?,?,?,?) on conflict(conversation_id,sender_id,client_id) do nothing', id, cid, u.id, body.client_id, text, body.reply_to ?? null, Date.now());
    const m = one('select * from messages where conversation_id=? and sender_id=? and client_id=?', cid, u.id, body.client_id);
    if (r.changes) publish(cid, { type: 'message.new', message: view(m, null) });
    return [r.changes ? 201 : 200, { message: view(m, u.id) }];
  });
  route('PATCH', '/api/messages/([^/]+)', true, ({ u, params, body }) => {
    const m = message(params[0], u.id);
    if (m.sender_id !== u.id || m.deleted_at) throw new HttpError(403, 'forbidden');
    run('update messages set body=?, edited_at=? where id=?', str(body.body, 1, 4000, 'body'), Date.now(), m.id);
    const nm = one('select * from messages where id=?', m.id); publish(m.conversation_id, { type: 'message.edited', message: view(nm, null) });
    return { message: view(nm, u.id) };
  });
  route('DELETE', '/api/messages/([^/]+)', true, ({ u, params }) => {
    const m = message(params[0], u.id), mem = member(m.conversation_id, u.id);
    if (m.sender_id !== u.id && !(['owner', 'admin'].includes(mem.role) && one('select kind from conversations where id=?', m.conversation_id).kind === 'group')) throw new HttpError(403, 'forbidden');
    run("update messages set body='', deleted_at=? where id=?", Date.now(), m.id);
    publish(m.conversation_id, { type: 'message.deleted', conversation_id: m.conversation_id, id: m.id }); return { ok: true };
  });
  route('PUT', '/api/messages/([^/]+)/reactions', true, ({ u, params, body }) => {
    const m = message(params[0], u.id); str(body.emoji, 1, 16, 'emoji');
    run('insert or ignore into reactions values(?,?,?)', m.id, u.id, body.emoji); publish(m.conversation_id, { type: 'reaction', message_id: m.id, conversation_id: m.conversation_id }); return { ok: true };
  });
  route('DELETE', '/api/messages/([^/]+)/reactions/([^/]+)', true, ({ u, params }) => {
    const m = message(params[0], u.id); run('delete from reactions where message_id=? and user_id=? and emoji=?', m.id, u.id, decodeURIComponent(params[1]));
    publish(m.conversation_id, { type: 'reaction', message_id: m.id, conversation_id: m.conversation_id }); return { ok: true };
  });

  // ---------- groups with roles and moderation log ----------
  const RANK = { member: 1, admin: 2, owner: 3 };
  const group = (cid, uid) => { const m = member(cid, uid); if (one('select kind from conversations where id=?', cid).kind !== 'group') throw new HttpError(404, 'not found'); return m; };
  route('POST', '/api/groups', true, ({ u, body }) => {
    const title = str(body.title, 1, 100, 'title'); const ids = Array.isArray(body.member_ids) ? [...new Set(body.member_ids)] : [];
    if (ids.length > 200 || ids.some(i => !UUID.test(i) || !one('select 1 x from users where id=?', i))) throw bad('invalid member_ids');
    return tx(() => {
      const id = crypto.randomUUID();
      run("insert into conversations(id,kind,title,created_by,created_at) values(?, 'group', ?, ?, ?)", id, title, u.id, Date.now());
      run("insert into members(conversation_id,user_id,role) values(?,?,'owner')", id, u.id);
      for (const i of ids) if (i !== u.id) run('insert or ignore into members(conversation_id,user_id) values(?,?)', id, i);
      return [201, { id }];
    });
  });
  route('POST', '/api/groups/([^/]+)/members', true, ({ u, params, body }) => {
    const me = group(params[0], u.id); if (RANK[me.role] < 2) throw new HttpError(403, 'forbidden');
    if (!UUID.test(body.user_id || '') || !one('select 1 x from users where id=?', body.user_id)) throw bad('invalid user');
    if (blocked(u.id, body.user_id)) throw new HttpError(403, 'blocked');
    run('insert or ignore into members(conversation_id,user_id) values(?,?)', params[0], body.user_id);
    run("insert into mod_log(conversation_id,actor_id,action,target_user,at) values(?,?,'add',?,?)", params[0], u.id, body.user_id, Date.now()); return { ok: true };
  });
  route('DELETE', '/api/groups/([^/]+)/members/([^/]+)', true, ({ u, params }) => {
    const me = group(params[0], u.id), target = UUID.test(params[1]) && one('select * from members where conversation_id=? and user_id=?', params[0], params[1]);
    if (!target) throw new HttpError(404, 'not found');
    if (params[1] === u.id) { if (me.role === 'owner') throw bad('owner cannot leave; delete or transfer the group'); }
    else if (RANK[me.role] < 2 || RANK[me.role] <= RANK[target.role]) throw new HttpError(403, 'forbidden');
    run('delete from members where conversation_id=? and user_id=?', params[0], params[1]);
    run("insert into mod_log(conversation_id,actor_id,action,target_user,at) values(?,?,'remove',?,?)", params[0], u.id, params[1], Date.now()); return { ok: true };
  });
  route('PATCH', '/api/groups/([^/]+)/members/([^/]+)', true, ({ u, params, body }) => {
    const me = group(params[0], u.id); if (me.role !== 'owner') throw new HttpError(403, 'forbidden');
    if (!['admin', 'member'].includes(body.role) || params[1] === u.id) throw bad('invalid role change');
    if (!run('update members set role=? where conversation_id=? and user_id=?', body.role, params[0], params[1]).changes) throw new HttpError(404, 'not found');
    run("insert into mod_log(conversation_id,actor_id,action,target_user,at) values(?,?,?,?,?)", params[0], u.id, 'role:' + body.role, params[1], Date.now()); return { ok: true };
  });
  route('GET', '/api/groups/([^/]+)/log', true, ({ u, params }) => {
    const me = group(params[0], u.id); if (RANK[me.role] < 2) throw new HttpError(403, 'forbidden');
    return { log: all('select actor_id, action, target_user, at from mod_log where conversation_id=? order by id desc limit 100', params[0]) };
  });

  // ---------- folders ----------
  function writeFolder(fid, uid, body) {
    const rules = Array.isArray(body.rules) ? body.rules : [], chats = Array.isArray(body.chats) ? body.chats : [];
    for (const r of rules) if (!RULES.includes(r?.rule) || !MODES.includes(r?.mode)) throw bad('invalid rule');
    for (const c of chats) { if (!MODES.includes(c?.mode)) throw bad('invalid chat mode'); member(c.conversation_id, uid); }
    run('delete from folder_rules where folder_id=?', fid); run('delete from folder_chats where folder_id=?', fid);
    for (const r of rules) run('insert or replace into folder_rules values(?,?,?)', fid, r.rule, r.mode);
    for (const c of chats) run('insert or replace into folder_chats values(?,?,?)', fid, c.conversation_id, c.mode);
  }
  const folder = (id, uid) => { const f = UUID.test(id) && one('select * from folders where id=? and user_id=?', id, uid); if (!f) throw new HttpError(404, 'not found'); return f; };
  route('GET', '/api/folders', true, ({ u }) => ({
    folders: all('select * from folders where user_id=? order by position, rowid', u.id).map(f => ({ ...f, rules: all('select rule, mode from folder_rules where folder_id=?', f.id), chats: all('select conversation_id, mode from folder_chats where folder_id=?', f.id), ...folderChats(db, u.id, f.id) })),
  }));
  route('POST', '/api/folders', true, ({ u, body }) => tx(() => {
    const id = crypto.randomUUID(), pos = one('select coalesce(max(position),-1)+1 p from folders where user_id=?', u.id).p;
    if (pos >= 50) throw bad('folder limit reached');
    run('insert into folders(id,user_id,name,icon,position) values(?,?,?,?,?)', id, u.id, str(body.name, 1, 32, 'name'), body.icon ? str(body.icon, 1, 32, 'icon') : 'folder', pos);
    writeFolder(id, u.id, body); return [201, { id }];
  }));
  route('PUT', '/api/folders/([^/]+)', true, ({ u, params, body }) => tx(() => {
    folder(params[0], u.id);
    if ('name' in body) run('update folders set name=? where id=?', str(body.name, 1, 32, 'name'), params[0]);
    if ('position' in body) { if (!Number.isInteger(body.position)) throw bad('position must be integer'); run('update folders set position=? where id=?', body.position, params[0]); }
    if ('rules' in body || 'chats' in body) writeFolder(params[0], u.id, body);
    return { ok: true };
  }));
  route('DELETE', '/api/folders/([^/]+)', true, ({ u, params }) => { folder(params[0], u.id); run('delete from folders where id=?', params[0]); return { ok: true }; });
  route('GET', '/api/folders/([^/]+)/chats', true, ({ u, params }) => { folder(params[0], u.id); return folderChats(db, u.id, params[0]); });

  // ---------- search (only chats the caller belongs to) ----------
  route('GET', '/api/search', true, ({ u, query }) => {
    const q = str(query.get('q') || '', 2, 100, 'q').replace(/[\\%_]/g, c => '\\' + c), cid = query.get('chat_id');
    if (cid) member(cid, u.id);
    const messages = all(`select m.* from messages m join members mm on mm.conversation_id=m.conversation_id and mm.user_id=? where m.deleted_at is null and m.body like ? escape '\\' and (? is null or m.conversation_id=?) order by m.seq desc limit 30`, u.id, `%${q}%`, cid, cid).map(m => view(m, u.id));
    return { messages };
  });
  route('GET', '/health', false, () => ({ ok: true }));

  // ---------- http plumbing ----------
  async function readBody(req) {
    let n = 0; const c = [];
    for await (const x of req) { n += x.length; if (n > 65536) throw new HttpError(413, 'payload too large'); c.push(x); }
    if (!n) return {};
    try { const j = JSON.parse(Buffer.concat(c)); if (!j || typeof j !== 'object' || Array.isArray(j)) throw 0; return j; } catch { throw bad('invalid JSON body'); }
  }
  const server = http.createServer(async (req, res) => {
    const send = (status, obj) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...(allowedOrigin ? { 'access-control-allow-origin': allowedOrigin, vary: 'origin' } : {}) }); res.end(JSON.stringify(obj)); };
    try {
      if (req.method === 'OPTIONS') { res.writeHead(204, allowedOrigin ? { 'access-control-allow-origin': allowedOrigin, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE' } : {}); return res.end(); }
      const url = new URL(req.url, 'http://x');
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = url.pathname.match(r.re); if (!m) continue;
        let u = null, token = null;
        if (r.auth) {
          const h = req.headers.authorization || ''; token = h.startsWith('Bearer ') ? h.slice(7) : null;
          const uid = token && uidFromToken(token); if (!uid) throw new HttpError(401, 'authentication required');
          u = one('select id, username, display_name from users where id=?', uid);
        }
        const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readBody(req) : {};
        const out = await r.fn({ req, u, token, body, params: m.slice(1), query: url.searchParams, ip: req.socket.remoteAddress });
        return Array.isArray(out) ? send(out[0], out[1]) : send(200, out);
      }
      throw new HttpError(404, 'not found');
    } catch (e) {
      if (e instanceof HttpError) return send(e.status, { error: e.message });
      console.error('internal error:', e.message);
      send(500, { error: 'internal error' });
    }
  });

  attachWs(server, {
    allowedOrigin, authToken: uidFromToken,
    onConnect: c => { if (!hub.has(c.uid)) hub.set(c.uid, new Set()); hub.get(c.uid).add(c); },
    onDisconnect: c => { const s = hub.get(c.uid); if (s) { s.delete(c); if (!s.size) hub.delete(c.uid); } },
    onClientMessage: (c, msg) => {
      if (msg.type === 'typing' && UUID.test(msg.conversation_id || '') && one('select 1 x from members where conversation_id=? and user_id=?', msg.conversation_id, c.uid))
        publish(msg.conversation_id, { type: 'typing', conversation_id: msg.conversation_id, user_id: c.uid }, c.uid);
    },
  });
  return { server, db, hub };
}
