# ChatSphere service

Working messaging backend: REST API + WebSocket realtime, SQLite storage, zero npm dependencies.
Requires Node 22.5+ (uses built-in `node:sqlite`, which Node marks experimental).

## Run
    cp .env.example .env      # then export the variables (or pass them inline)
    npm test                  # 14 tests: auth, authorization, dedupe, folders, groups, blocking, search, WebSocket, rate limit
    PORT=3000 npm start
    curl localhost:3000/health

## API (JSON, `Authorization: Bearer <token>`)
| Method + path | Purpose |
|---|---|
| POST /api/register, /api/login | returns `{token, user}`; rate limited per IP |
| POST /api/logout, /api/logout-others | end this / all other sessions |
| GET /api/me, PATCH /api/settings, DELETE /api/me | profile, read-receipt setting, delete account (`{confirm: username}`) |
| GET /api/users?q= | username prefix search (hides users who blocked you) |
| POST /api/blocks, DELETE /api/blocks/:userId, POST /api/reports | block / report a user or message |
| POST /api/chats/direct, /api/chats/saved | open a direct chat / Saved messages |
| GET /api/chats?folder_id=&archived=1 | chat list with unread, pins, last message |
| PATCH /api/chats/:id/prefs, POST /api/chats/:id/read | mute, archive, pin, favorite; mark read |
| GET/POST /api/chats/:id/messages | history (`before`, `limit`) / send (`client_id` UUID, `body`, `reply_to`) |
| PATCH/DELETE /api/messages/:id | edit (sender) / delete (sender, or group admin) |
| PUT/DELETE /api/messages/:id/reactions | emoji reactions |
| POST /api/groups, /api/groups/:id/members, PATCH/DELETE .../members/:uid, GET .../log | groups, roles (owner/admin/member), moderation log |
| GET/POST /api/folders, PUT/DELETE /api/folders/:id, GET /api/folders/:id/chats | smart folders with rules and unread totals |
| GET /api/search?q=&chat_id= | message search, limited to chats you belong to |

WebSocket: connect to `/ws`, send `{"type":"auth","token":"..."}` within 5 s. Server events: `ready`, `message.new`,
`message.edited`, `message.deleted`, `reaction`, `read`, `typing`. Client may send `{"type":"typing","conversation_id":"..."}`.
Reconnect-safe sending: retry with the same `client_id`; the server returns the existing message instead of duplicating it.

## Folder rule resolution
1. explicit per-chat exclude, 2. explicit per-chat include, 3. any matching exclude rule, 4. any matching include rule, 5. otherwise not in folder.
Rules: unread, muted, archived, group, direct, favorite. No AI classification.

## Security model
Passwords: scrypt with per-user salt. Session tokens: 32 random bytes, only their SHA-256 is stored, 30-day expiry.
Every chat/message route checks membership (non-members get 404). Input is validated server-side, bodies capped at 64 KB,
SQL is parameterised, LIKE input is escaped, CORS and WebSocket origin are limited to `ALLOWED_ORIGIN`.
Messages are NOT end-to-end encrypted. Transport security needs HTTPS/WSS from a reverse proxy (Caddy, nginx).

## Known limits (not built)
Single process: rate limiter and WebSocket hub live in memory, SQLite is one file, so no horizontal scaling.
Not included: email verification/password reset (needs an email provider), media uploads, push notifications, calls (WebRTC),
channels, stories, polls, admin dashboard, WebSocket heartbeat. `supabase/migrations/0001_core.sql` is a separate, untested
Postgres/Supabase schema for a later migration; this service does not use it.
