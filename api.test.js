import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createApp } from '../src/server.js';

const app = createApp({ limit: 1000 });
await new Promise(r => app.server.listen(0, '127.0.0.1', r));
const port = app.server.address().port;
const base = `http://127.0.0.1:${port}`;
test.after(() => app.server.close());

async function api(method, path, body, token) {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json() };
}
async function signup(name) {
  const r = await api('POST', '/api/register', { username: name, password: 'correct-horse-battery' });
  assert.equal(r.status, 201); return { token: r.json.token, id: r.json.user.id };
}
const uuid = () => crypto.randomUUID();
const send = (chat, token, body, extra = {}) => api('POST', `/api/chats/${chat}/messages`, { client_id: uuid(), body, ...extra }, token);

const alice = await signup('alice'), bob = await signup('bob'), carol = await signup('carol');
const dm = (await api('POST', '/api/chats/direct', { user_id: bob.id }, alice.token)).json.id;

test('registration, login and session rules', async () => {
  assert.equal((await api('POST', '/api/register', { username: 'alice', password: 'correct-horse-battery' })).status, 409);
  assert.equal((await api('POST', '/api/register', { username: 'dave', password: 'short' })).status, 400);
  assert.equal((await api('POST', '/api/login', { username: 'alice', password: 'wrong-password' })).status, 401);
  assert.equal((await api('POST', '/api/login', { username: 'nobody', password: 'whatever-123' })).status, 401);
  const l = await api('POST', '/api/login', { username: 'ALICE', password: 'correct-horse-battery' });
  assert.equal(l.status, 200);
  assert.equal((await api('GET', '/api/me')).status, 401);
  assert.equal((await api('GET', '/api/me', null, 'bogus')).status, 401);
  assert.equal((await api('GET', '/api/me', null, l.json.token)).json.user.username, 'alice');
  await api('POST', '/api/logout', {}, l.json.token);
  assert.equal((await api('GET', '/api/me', null, l.json.token)).status, 401);
});

test('passwords are never stored in plaintext', () => {
  const row = app.db.prepare("select pass_hash from users where username='alice'").get();
  assert.ok(!row.pass_hash.includes('correct-horse'));
  assert.match(row.pass_hash, /^[0-9a-f]{32}:[0-9a-f]{128}$/);
});

test('private conversation authorization', async () => {
  const m = await send(dm, alice.token, 'hello bob');
  assert.equal(m.status, 201);
  assert.equal((await api('GET', `/api/chats/${dm}/messages`, null, carol.token)).status, 404);
  assert.equal((await send(dm, carol.token, 'intruder')).status, 404);
  assert.equal((await api('PATCH', `/api/messages/${m.json.message.id}`, { body: 'x' }, carol.token)).status, 404);
  const h = await api('GET', `/api/chats/${dm}/messages`, null, bob.token);
  assert.equal(h.json.messages.length, 1);
});

test('duplicate send protection and pagination', async () => {
  const cid = uuid(), a = await api('POST', `/api/chats/${dm}/messages`, { client_id: cid, body: 'once' }, alice.token);
  const b = await api('POST', `/api/chats/${dm}/messages`, { client_id: cid, body: 'once' }, alice.token);
  assert.equal(a.status, 201); assert.equal(b.status, 200); assert.equal(a.json.message.id, b.json.message.id);
  for (let i = 0; i < 5; i++) await send(dm, bob.token, 'msg ' + i);
  const p1 = await api('GET', `/api/chats/${dm}/messages?limit=3`, null, alice.token);
  assert.equal(p1.json.messages.length, 3);
  const p2 = await api('GET', `/api/chats/${dm}/messages?limit=3&before=${p1.json.next_before}`, null, alice.token);
  assert.ok(p2.json.messages.every(x => x.seq < p1.json.next_before));
  assert.equal((await send(dm, alice.token, 'x'.repeat(4001))).status, 400);
  assert.equal((await api('POST', `/api/chats/${dm}/messages`, { client_id: 'nope', body: 'hi' }, alice.token)).status, 400);
});

test('edit and delete permissions, replies, reactions', async () => {
  const m = (await send(dm, alice.token, 'original')).json.message;
  assert.equal((await api('PATCH', `/api/messages/${m.id}`, { body: 'hacked' }, bob.token)).status, 403);
  const e = await api('PATCH', `/api/messages/${m.id}`, { body: 'edited' }, alice.token);
  assert.equal(e.json.message.body, 'edited'); assert.ok(e.json.message.edited_at);
  const r = await send(dm, bob.token, 'reply', { reply_to: m.id });
  assert.equal(r.json.message.reply_to, m.id);
  assert.equal((await send(dm, bob.token, 'bad reply', { reply_to: uuid() })).status, 400);
  await api('PUT', `/api/messages/${m.id}/reactions`, { emoji: '👍' }, bob.token);
  const h = await api('GET', `/api/chats/${dm}/messages?limit=100`, null, bob.token);
  assert.deepEqual(h.json.messages.find(x => x.id === m.id).reactions, [{ emoji: '👍', count: 1, mine: true }]);
  assert.equal((await api('DELETE', `/api/messages/${m.id}`, null, bob.token)).status, 403);
  assert.equal((await api('DELETE', `/api/messages/${m.id}`, null, alice.token)).status, 200);
  const h2 = await api('GET', `/api/chats/${dm}/messages?limit=100`, null, bob.token);
  const gone = h2.json.messages.find(x => x.id === m.id); assert.equal(gone.deleted, true); assert.equal(gone.body, '');
});

test('unread counts and mark read', async () => {
  const dm2 = (await api('POST', '/api/chats/direct', { user_id: carol.id }, alice.token)).json.id;
  await send(dm2, carol.token, 'one'); await send(dm2, carol.token, 'two');
  const c1 = (await api('GET', '/api/chats', null, alice.token)).json.chats.find(c => c.id === dm2);
  assert.equal(c1.unread, 2);
  await api('POST', `/api/chats/${dm2}/read`, {}, alice.token);
  const c2 = (await api('GET', '/api/chats', null, alice.token)).json.chats.find(c => c.id === dm2);
  assert.equal(c2.unread, 0);
});

test('folders: rule engine, explicit overrides, unread totals', async () => {
  const dave = await signup('dave2'), erin = await signup('erin2');
  const d1 = (await api('POST', '/api/chats/direct', { user_id: erin.id }, dave.token)).json.id;
  const grp = (await api('POST', '/api/groups', { title: 'Crew', member_ids: [erin.id] }, dave.token)).json.id;
  await send(d1, erin.token, 'ping'); await send(grp, erin.token, 'group ping');
  const f = (await api('POST', '/api/folders', { name: 'Unread DMs', rules: [{ rule: 'unread', mode: 'include' }, { rule: 'group', mode: 'exclude' }] }, dave.token)).json.id;
  let r = (await api('GET', `/api/folders/${f}/chats`, null, dave.token)).json;
  assert.deepEqual(r.chats, [d1]); assert.equal(r.unread, 1);
  await api('PUT', `/api/folders/${f}`, { chats: [{ conversation_id: grp, mode: 'include' }, { conversation_id: d1, mode: 'exclude' }] }, dave.token);
  r = (await api('GET', `/api/folders/${f}/chats`, null, dave.token)).json;
  assert.deepEqual(r.chats, [grp]);
  const filtered = (await api('GET', `/api/chats?folder_id=${f}`, null, dave.token)).json.chats;
  assert.deepEqual(filtered.map(c => c.id), [grp]);
  assert.equal((await api('GET', `/api/folders/${f}/chats`, null, erin.token)).status, 404);
  assert.equal((await api('POST', '/api/folders', { name: 'x', rules: [{ rule: 'bogus', mode: 'include' }] }, dave.token)).status, 400);
  await api('PATCH', `/api/chats/${d1}/prefs`, { pinned: true, archived: true }, dave.token);
  assert.equal((await api('GET', '/api/chats', null, dave.token)).json.chats.some(c => c.id === d1), false);
  assert.equal((await api('GET', '/api/chats?archived=1', null, dave.token)).json.chats.some(c => c.id === d1), true);
});

test('groups: roles and moderation log', async () => {
  const g = (await api('POST', '/api/groups', { title: 'Team', member_ids: [bob.id] }, alice.token)).json.id;
  assert.equal((await api('POST', `/api/groups/${g}/members`, { user_id: carol.id }, bob.token)).status, 403);
  assert.equal((await api('POST', `/api/groups/${g}/members`, { user_id: carol.id }, alice.token)).status, 200);
  assert.equal((await api('PATCH', `/api/groups/${g}/members/${carol.id}`, { role: 'admin' }, bob.token)).status, 403);
  await api('PATCH', `/api/groups/${g}/members/${carol.id}`, { role: 'admin' }, alice.token);
  assert.equal((await api('DELETE', `/api/groups/${g}/members/${alice.id}`, null, carol.token)).status, 403);
  assert.equal((await api('DELETE', `/api/groups/${g}/members/${bob.id}`, null, carol.token)).status, 200);
  assert.equal((await api('GET', `/api/chats/${g}/messages`, null, bob.token)).status, 404);
  assert.equal((await api('GET', `/api/groups/${g}/log`, null, bob.token)).status, 404);
  assert.ok((await api('GET', `/api/groups/${g}/log`, null, alice.token)).json.log.length >= 3);
  const m = (await send(g, bob.token, 'x')).status; assert.equal(m, 404);
});

test('blocking and reporting', async () => {
  const x = await signup('xavier'), y = await signup('yolanda');
  const c = (await api('POST', '/api/chats/direct', { user_id: y.id }, x.token)).json.id;
  assert.equal((await send(c, x.token, 'hi')).status, 201);
  await api('POST', '/api/blocks', { user_id: x.id }, y.token);
  assert.equal((await send(c, x.token, 'still there?')).status, 403);
  assert.equal((await send(c, y.token, 'reply')).status, 403);
  assert.equal((await api('POST', '/api/chats/direct', { user_id: y.id }, x.token)).status, 403);
  assert.equal((await api('GET', '/api/users?q=yol', null, x.token)).json.users.length, 0, 'blocked user cannot find the blocker');
  const msg = (await api('GET', `/api/chats/${c}/messages`, null, y.token)).json.messages[0];
  assert.equal((await api('POST', '/api/reports', { message_id: msg.id, reason: 'spam' }, y.token)).status, 201);
  assert.equal((await api('POST', '/api/reports', { message_id: msg.id, reason: 'spam' }, carol.token)).status, 404);
  await api('DELETE', `/api/blocks/${x.id}`, null, y.token);
  assert.equal((await send(c, x.token, 'sorry')).status, 201);
});

test('search only covers chats the caller belongs to', async () => {
  await send(dm, alice.token, 'needle-in-private-chat');
  const a = await api('GET', '/api/search?q=needle', null, alice.token);
  assert.ok(a.json.messages.length >= 1);
  assert.equal((await api('GET', '/api/search?q=needle', null, carol.token)).json.messages.length, 0);
  assert.equal((await api('GET', `/api/search?q=needle&chat_id=${dm}`, null, carol.token)).status, 404);
  assert.equal((await api('GET', '/api/search?q=%25%25', null, alice.token)).json.messages.length, 0);
});

test('request hardening', async () => {
  const r = await fetch(base + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad json' });
  assert.equal(r.status, 400);
  const big = await fetch(base + '/api/login', { method: 'POST', body: 'x'.repeat(70000) }).catch(() => ({ status: 413 }));
  assert.ok([413].includes(big.status));
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

test('account deletion removes data', async () => {
  const z = await signup('zed_del');
  assert.equal((await api('DELETE', '/api/me', { confirm: 'wrong' }, z.token)).status, 400);
  assert.equal((await api('DELETE', '/api/me', { confirm: 'zed_del' }, z.token)).status, 200);
  assert.equal((await api('GET', '/api/me', null, z.token)).status, 401);
});

function wsClient(token) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`), events = [];
  const waiters = [];
  ws.onmessage = e => { const d = JSON.parse(e.data); events.push(d); waiters.splice(0).forEach(w => w()); };
  const waitFor = (pred, ms = 2000) => new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('timeout')), ms);
    const check = () => { const f = events.find(pred); if (f) { clearTimeout(t); res(f); } else waiters.push(check); };
    check();
  });
  const opened = new Promise(r => { ws.onopen = () => { if (token) ws.send(JSON.stringify({ type: 'auth', token })); r(); }; });
  const closed = new Promise(r => { ws.onclose = e => r(e.code); });
  return { ws, events, waitFor, opened, closed };
}

test('websocket: auth, realtime delivery, typing, bad token', async () => {
  const b = wsClient(bob.token); await b.opened; await b.waitFor(e => e.type === 'ready');
  const m = await send(dm, alice.token, 'live message');
  const ev = await b.waitFor(e => e.type === 'message.new' && e.message.id === m.json.message.id);
  assert.equal(ev.message.body, 'live message');
  const a = wsClient(alice.token); await a.opened; await a.waitFor(e => e.type === 'ready');
  b.ws.send(JSON.stringify({ type: 'typing', conversation_id: dm }));
  assert.equal((await a.waitFor(e => e.type === 'typing')).user_id, bob.id);
  const c = wsClient(carol.token); await c.opened; await c.waitFor(e => e.type === 'ready');
  await send(dm, alice.token, 'carol must not see this');
  await new Promise(r => setTimeout(r, 150));
  assert.equal(c.events.filter(e => e.type === 'message.new').length, 0);
  const bad = wsClient('not-a-token'); await bad.opened;
  assert.equal(await bad.closed, 4401);
  [a, b, c].forEach(x => x.ws.close());
});
