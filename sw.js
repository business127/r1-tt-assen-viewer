// Service worker van de afgeschermde viewer (gemaakt door tools/versleutel.mjs bij het publiceren).
// Op GitHub Pages staat alles versleuteld (AES-256-GCM) onder x/<naam>. De naam is een HMAC van het pad, dus zonder
// wachtwoord zijn de bestandsnamen ook niet te raden. Na het inloggen staan de sleutels (niet uitleesbaar) in IndexedDB;
// deze worker haalt bij elk verzoek het versleutelde bestand op en geeft het ontsleuteld terug. De app merkt daar niets van.
const VERSIE = 'b1e9b58';
const OPEN = new Set(['', 'index.html', 'sw.js', '404.html', 'login.css', 'README.md', 'robots.txt']);   // niet versleuteld
const TYPES = { html: 'text/html; charset=utf-8', mjs: 'text/javascript; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8', json: 'application/json', csv: 'text/csv; charset=utf-8', md: 'text/markdown; charset=utf-8', txt: 'text/plain; charset=utf-8', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', svg: 'image/svg+xml', woff2: 'font/woff2', glb: 'model/gltf-binary', bin: 'application/octet-stream' };
const DUUR = 30 * 24 * 3600 * 1000;   // ingelogd blijven: 30 dagen

// Tekst en data staan gecomprimeerd (gzip) in de versleuteling; herkenbaar aan 1f 8b (zie tools/versleutel.mjs).
const ZIP = new Set(['json', 'mjs', 'js', 'csv', 'css', 'txt', 'md', 'svg', 'bin', 'glb']);

// Vervangt deze worker een oudere (nieuwe publicatie), dan kan een open viewer half met de oude geladen zijn: die
// pagina's één keer herladen, zodat alles via deze worker komt. Het inlogscherm laten we met rust.
let vervangt = false;
self.addEventListener('install', () => { vervangt = !!self.registration.active; self.skipWaiting(); });
self.addEventListener('activate', e => e.waitUntil(self.clients.claim().then(async () => {
  if (!vervangt) return;
  for (const c of await self.clients.matchAll({ type: 'window' })) {
    const p = new URL(c.url).pathname.slice(basis().length);
    if (p && !OPEN.has(p) && !p.startsWith('?') && 'navigate' in c) c.navigate(c.url).catch(() => {});
  }
})));

let sleutels = null;   // { aes, hmac, t }
function leesSleutels() {
  return new Promise(res => {
    const r = indexedDB.open('aero', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onerror = () => res(null);
    r.onsuccess = () => { const tx = r.result.transaction('k', 'readonly').objectStore('k').get('sleutel'); tx.onsuccess = () => res(tx.result || null); tx.onerror = () => res(null); };
  });
}
async function wisSleutels() {
  sleutels = null;
  await new Promise(res => { const r = indexedDB.open('aero', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onerror = res; r.onsuccess = () => { const tx = r.result.transaction('k', 'readwrite'); tx.objectStore('k').delete('sleutel'); tx.oncomplete = res; tx.onerror = res; }; });
}
self.addEventListener('message', e => { if (e.data === 'uit') e.waitUntil(wisSleutels()); });

async function naarSleutel(s) {   // ruwe bytes (terugval als de browser geen CryptoKey in IndexedDB kan bewaren)
  if (!s || s.aes instanceof CryptoKey) return s;
  return { t: s.t, aes: await crypto.subtle.importKey('raw', s.aes, 'AES-GCM', false, ['decrypt']), hmac: await crypto.subtle.importKey('raw', s.hmac, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']) };
}
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function naam(pad) { return hex(await crypto.subtle.sign('HMAC', sleutels.hmac, new TextEncoder().encode(pad))).slice(0, 40); }

const basis = () => new URL(self.registration.scope).pathname;
function naarLogin(pad) { return Response.redirect(basis() + '?terug=' + encodeURIComponent(pad), 302); }

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || e.request.method !== 'GET') return;
  const b = basis();
  if (!url.pathname.startsWith(b)) return;
  let pad; try { pad = decodeURIComponent(url.pathname.slice(b.length)); } catch { return; }
  if (OPEN.has(pad) || pad.startsWith('login/') || pad.startsWith('x/')) return;
  if (pad === '' || pad.endsWith('/')) pad += 'index.html';
  e.respondWith(lever(e.request, pad));
});

async function lever(req, pad) {
  const nav = req.mode === 'navigate';
  if (!sleutels || nav) sleutels = await naarSleutel(await leesSleutels());
  if (sleutels && Date.now() - sleutels.t > DUUR) await wisSleutels();
  if (!sleutels) return nav ? naarLogin(pad) : new Response('Niet ingelogd', { status: 401 });
  const r = await fetch(`x/${await naam(pad)}?v=${VERSIE}`, { cache: nav || req.cache === 'no-store' || req.cache === 'reload' ? 'no-cache' : 'default' });
  if (!r.ok) return new Response('Niet gevonden', { status: 404 });
  const buf = await r.arrayBuffer();
  const ext = pad.split('.').pop().toLowerCase();
  let inhoud;
  try { inhoud = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12), additionalData: new TextEncoder().encode(pad) }, sleutels.aes, new Uint8Array(buf, 12)); }
  catch { await wisSleutels(); return nav ? naarLogin(pad) : new Response('Sleutel klopt niet', { status: 403 }); }
  const k = new Uint8Array(inhoud, 0, Math.min(2, inhoud.byteLength)), gz = ZIP.has(ext) && k[0] === 0x1f && k[1] === 0x8b;
  const body = gz ? new Response(inhoud).body.pipeThrough(new DecompressionStream('gzip')) : inhoud;
  return new Response(body, { status: 200, headers: { 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' } });
}
