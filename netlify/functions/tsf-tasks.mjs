// Growth Panel tasks (soylu.dev/tsf, #tasks): a shared to-do list for the store admins.
// Source: ~/tools/tsf/tsf-cc/.claude/growth-panel/site/netlify/tsf-tasks.mjs, copied into the website by build.mjs
// (which fills in TOKEN_CHECK). Do not edit the copy in the website.
//
// Every task is encrypted in the browser with the panel password (AES-256-GCM) before it is sent: Netlify only ever
// stores { iv, ct }. Writing and reading need the header X-TSF-Token = a value only the password can produce
// (sha256 of the derived key); this file holds only sha256 of that token, so the public repo gives nothing away.
//
//   GET    /tsf/api/tasks                 -> { tasks: [{ id, etag, sealed }] }
//   PUT    /tsf/api/tasks?id=<id>         body { sealed, etag? }  (etag = the version you edited; none = new task)
//   DELETE /tsf/api/tasks?id=<id>&etag=<etag>
// A PUT or DELETE on a version someone else changed meanwhile answers 409, so nobody overwrites another's edit.
import { getStore } from '@netlify/blobs';
import { createHash, timingSafeEqual } from 'node:crypto';

const TOKEN_CHECK = 'f3120cc1fe661e4914062ec4d3f68231e208a266d84b55f4e4e3c945fe92f28e';
const MAX_TASKS = 1000;
const MAX_SEALED = 16 * 1024;
const ID = /^[a-z0-9]{8,32}$/;

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const sha = (s) => createHash('sha256').update(String(s)).digest();
const authorized = (req) => {
  const t = req.headers.get('x-tsf-token') || '';
  return t.length === 64 && timingSafeEqual(sha(t), Buffer.from(TOKEN_CHECK, 'hex'));
};
const validSealed = (s) => s && typeof s.iv === 'string' && typeof s.ct === 'string' && s.iv.length <= 32 && JSON.stringify(s).length <= MAX_SEALED;

export default async (req) => {
  if (!authorized(req)) return json(401, { error: 'wrong or missing token' });
  const store = getStore({ name: 'tsf-tasks', consistency: 'strong' });
  const url = new URL(req.url);
  const id = url.searchParams.get('id');

  if (req.method === 'GET') {
    const { blobs } = await store.list();
    const tasks = (await Promise.all(blobs.map(async (b) => {
      const r = await store.getWithMetadata(b.key, { type: 'json' });
      return r ? { id: b.key, etag: r.etag, sealed: r.data } : null;
    }))).filter(Boolean);
    return json(200, { tasks });
  }

  if (!id || !ID.test(id)) return json(400, { error: 'bad id' });

  if (req.method === 'PUT') {
    let body;
    try { body = await req.json(); } catch { return json(400, { error: 'bad json' }); }
    if (!validSealed(body.sealed)) return json(400, { error: 'bad task' });
    if (!body.etag) {
      const { blobs } = await store.list();
      if (blobs.length >= MAX_TASKS) return json(507, { error: 'too many tasks' });
    }
    const sealed = { iv: body.sealed.iv, ct: body.sealed.ct };
    const res = await store.setJSON(id, sealed, body.etag ? { onlyIfMatch: body.etag } : { onlyIfNew: true });
    if (!res.modified) return json(409, { error: 'changed by someone else; reload' });
    return json(200, { id, etag: res.etag });
  }

  if (req.method === 'DELETE') {
    const cur = await store.getWithMetadata(id, { type: 'json' });
    if (!cur) return json(200, { id, deleted: true });
    if (cur.etag !== url.searchParams.get('etag')) return json(409, { error: 'changed by someone else; reload' });
    await store.delete(id);
    return json(200, { id, deleted: true });
  }

  return json(405, { error: 'method not allowed' });
};

export const config = { path: '/tsf/api/tasks' };
