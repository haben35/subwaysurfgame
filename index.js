import { createApp } from './server.js';
const { server } = createApp({
  dbFile: process.env.DB_FILE || './chatsphere.db',
  limit: Number(process.env.AUTH_RATE_LIMIT || 10),
  allowedOrigin: process.env.ALLOWED_ORIGIN || '',
});
const port = Number(process.env.PORT || 3000);
server.listen(port, () => console.log(`ChatSphere service listening on :${port}`));
