// Cloudflare Worker in front of your app, backed by Undertow.
// Vars/secrets: UNDERTOW_VERDICT_URL, UNDERTOW_KEY (a verdict key), and for the cell:
// UNDERTOW_CELL_ORIGIN (https://<CellOriginDomain>) + UNDERTOW_ORIGIN_SECRET. Fails open.
const GENERIC = '{"error":"request could not be processed"}';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let v = { verdict: "allow" };
    try {
      const r = await fetch(env.UNDERTOW_VERDICT_URL, {
        method: "POST",
        headers: { authorization: `Bearer ${env.UNDERTOW_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({
          ip: request.headers.get("cf-connecting-ip"), method: request.method, path: url.pathname,
          query: url.search.slice(1), headers: Object.fromEntries(request.headers),
          ja4: (request.cf && request.cf.botManagement && request.cf.botManagement.ja4) || "",
        }),
        signal: AbortSignal.timeout(1000),
      });
      if (r.ok) v = await r.json();
    } catch (_) { /* fail open: Undertow down never means the site is down */ }

    if (v.verdict === "block") return new Response(GENERIC, { status: 403, headers: { "content-type": "application/json" } });
    if (v.verdict === "tarpit") {
      return new Response(GENERIC, { status: 429, headers: { "content-type": "application/json", "retry-after": "9" } });
    }
    if (v.verdict === "cell" && env.UNDERTOW_CELL_ORIGIN) {
      const h = new Headers(request.headers);
      h.set("x-origin-verify", env.UNDERTOW_ORIGIN_SECRET || "");
      return fetch(new Request(env.UNDERTOW_CELL_ORIGIN + url.pathname + url.search,
                               { method: request.method, headers: h, body: request.body }));
    }
    const h = new Headers(request.headers);
    h.set("x-undertow-verdict", v.verdict || "allow");
    return fetch(new Request(request, { headers: h }));
  },
};
