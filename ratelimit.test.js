import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';

test('login attempts are rate limited', async () => {
  const { server } = createApp({ limit: 3 });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/api/login`;
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await fetch(url, { method: 'POST', body: JSON.stringify({ username: 'x', password: 'y' }) })).status);
  assert.deepEqual(codes, [401, 401, 401, 429, 429]);
  server.close();
});
