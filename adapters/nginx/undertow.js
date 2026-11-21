// nginx njs: ask Undertow before proxying. See undertow.conf. Fails open: an unreachable
// Undertow never takes the site down.
async function verdict(r) {
  const body = JSON.stringify({
    ip: r.variables.remote_addr,
    method: r.variables.ut_method,
    path: (r.variables.request_uri || "/").split("?")[0],
    query: r.variables.args || "",
    headers: r.headersIn,
  });
  let v = "allow";
  try {
    const res = await ngx.fetch(r.variables.ut_url, {
      method: "POST", body, headers: { authorization: "Bearer " + r.variables.ut_key, "content-type": "application/json" },
    });
    if (res.ok) v = (await res.json()).verdict || "allow";
  } catch (e) { /* fail open */ }
  r.headersOut["X-Undertow-Verdict"] = v;
  r.return(v === "block" ? 403 : 204);
}

export default { verdict };
