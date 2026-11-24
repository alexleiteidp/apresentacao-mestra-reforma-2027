// Entrega os arquivos da apresentação já decifrados, depois que a senha foi aceita na página de entrada.
// A chave fica guardada só neste navegador (IndexedDB), em formato que não pode ser exportado.
const BANCO = "apresentacao-protegida";
let estado = null; // { chave, mapa }

function abrir() {
  return new Promise((ok, erro) => {
    const p = indexedDB.open(BANCO, 1);
    p.onupgradeneeded = () => p.result.createObjectStore("kv");
    p.onsuccess = () => ok(p.result); p.onerror = () => erro(p.error);
  });
}
async function lerEstado() {
  if (estado) return estado;
  const db = await abrir();
  const v = await new Promise((ok) => { const r = db.transaction("kv").objectStore("kv").get("estado"); r.onsuccess = () => ok(r.result); r.onerror = () => ok(null); });
  db.close();
  return (estado = v || null);
}
async function decifrar(chave, url) {
  const r = await fetch(url, { cache: "force-cache" });
  if (!r.ok) throw new Error(url + ": " + r.status);
  const b = new Uint8Array(await r.arrayBuffer());
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, chave, b.slice(12));
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => { if (e.data === "recarregar") estado = null; });

self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url), base = new URL(self.registration.scope);
  if (u.origin !== base.origin || !u.pathname.startsWith(base.pathname) || e.request.method !== "GET") return;
  let rel = decodeURIComponent(u.pathname.slice(base.pathname.length)) || "index.html";
  if (rel === "sw.js" || rel.startsWith("d/")) return;
  e.respondWith((async () => {
    const s = await lerEstado();
    if (!s) return fetch(e.request); // sem senha: vale o que está publicado (a página de entrada)
    const a = s.mapa[rel];
    if (!a) return new Response("Não encontrado", { status: 404 });
    try {
      const dados = await decifrar(s.chave, base.href + "d/" + a.n + ".bin");
      const cab = { "Content-Type": a.tipo, "Accept-Ranges": "bytes", "Cache-Control": "no-store" };
      const faixa = /^bytes=(\d+)-(\d*)$/.exec(e.request.headers.get("Range") || "");
      if (faixa) { // vídeos: alguns navegadores pedem o arquivo em partes
        const ini = +faixa[1], fim = Math.min(faixa[2] ? +faixa[2] : dados.byteLength - 1, dados.byteLength - 1);
        return new Response(dados.slice(ini, fim + 1), { status: 206, headers: { ...cab, "Content-Range": `bytes ${ini}-${fim}/${dados.byteLength}` } });
      }
      return new Response(dados, { headers: cab });
    } catch (erro) {
      return new Response("Falha ao abrir o arquivo", { status: 500 });
    }
  })());
});
