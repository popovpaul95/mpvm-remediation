// Загрузка content/api.js и content/logic.js в изолированный vm-контекст без сети и без браузера.
// VR.pdql/get/post/put/del подменяются заглушками, которые по умолчанию падают: тест обязан задать нужный ответ.
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function loadVR({ now, ext } = {}) {
  const calls = { pdql: [], get: [], post: [], put: [], del: [], ext: [] };
  const ctx = {
    console, URLSearchParams,
    setTimeout: fn => { Promise.resolve().then(fn); return 0; }, clearTimeout() {},
    location: { protocol: 'https:', hostname: 'mp.test', origin: 'https://mp.test', href: 'https://mp.test/' },
    fetch: async () => { throw new Error('сеть в unit-тестах отключена'); },
    chrome: {
      storage: { sync: { get: (k, cb) => cb({ host: 'mp.test', port: '', token: 'pat_test' }) }, onChanged: { addListener() {} } },
      runtime: { lastError: null, onMessage: { addListener() {} }, sendMessage: (msg, cb) => { calls.ext.push(msg); cb({ ok: true, result: ext ? ext(msg.op, msg.params) : null }); } },
    },
  };
  ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx);
  if (now) vm.runInContext(`var __RealDate = Date; Date = class extends __RealDate { constructor(...a) { super(...(a.length ? a : [${JSON.stringify(now)}])); } static now() { return new __RealDate(${JSON.stringify(now)}).getTime(); } };`, ctx);
  for (const f of ['content/api.js', 'content/logic.js']) vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), ctx, { filename: f });
  const VR = ctx.VR;
  VR.pdql = async (pdql, limit, offset) => { calls.pdql.push({ pdql, limit, offset }); return { records: [] }; };
  VR.get = async p => { calls.get.push(p); throw new Error('VR.get не подменен: ' + p); };
  VR.post = async (p, b) => { calls.post.push({ p, b }); throw new Error('VR.post не подменен: ' + p); };
  VR.put = async (p, b) => { calls.put.push({ p, b }); throw new Error('VR.put не подменен: ' + p); };
  VR.del = async p => { calls.del.push(p); throw new Error('VR.del не подменен: ' + p); };
  return { VR, calls, ctx };
}

// Разэкранирование строкового литерала PDQL ("a\"b\\c" -> a"b\c)
export const unescPdql = s => s.replace(/\\(["\\])/g, '$1');

// Объекты из vm-контекста имеют другие прототипы Array/Object: для deepStrictEqual сравниваем простые копии
export const plain = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
export const deq = (actual, expected, msg) => msg === undefined ? assertStrict.deepEqual(plain(actual), plain(expected)) : assertStrict.deepEqual(plain(actual), plain(expected), msg);
import assertStrict from 'node:assert/strict';
