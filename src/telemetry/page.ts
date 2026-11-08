// telemetry lane: "What we send" admin page, served by relaycontrol at
// /cloud/api/v1/telemetry/admin (same-origin, uses the dashboard session
// cookie). It renders the exact next payload and the queued outbox entries.
// A relay-dashboard Settings route can later embed the same JSON endpoints.
export function adminPage(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Telemetry: what we send</title>
<style>
:root{color-scheme:light dark;--fg:#171717;--muted:#5c5c5c;--bg:#fff;--panel:#f5f5f4;--line:#e5e5e5}
@media (prefers-color-scheme:dark){:root{--fg:#ededed;--muted:#a3a3a3;--bg:#111;--panel:#1c1c1c;--line:#2e2e2e}}
body{font:15px/1.5 system-ui;margin:0;background:var(--bg);color:var(--fg)}
main{max-width:64rem;margin:0 auto;padding:1.5rem 1rem}
h1{font-size:1.4rem;margin:.2rem 0}h2{font-size:1.05rem;margin:1.6rem 0 .4rem}
.muted{color:var(--muted)}dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:0}
dt{color:var(--muted)}pre{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:.8rem;overflow:auto;max-height:32rem;font-size:12.5px}
button,a.button{font:inherit;padding:.35rem .8rem;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg);cursor:pointer;text-decoration:none;margin-right:.4rem}
select{font:inherit;padding:.3rem}
</style></head><body><main>
<p class="muted"><a href="/" class="muted">Dashboard</a> / Settings / Telemetry</p>
<h1>Telemetry: what we send</h1>
<p class="muted">Only aggregates and scrubbed error metadata leave this cluster. Message content, transcripts, prompts, file contents, secrets, emails and user names are never sent. Identifiers are hashed with a salt that stays in this install.</p>
<div id="error" role="alert"></div>
<h2>Status</h2><dl id="status"><dt>Loading</dt><dd>…</dd></dl>
<h2>Next digest</h2>
<p><label>Preview at level <select id="level"><option value="">configured</option><option>errors</option><option>full</option></select></label>
<button id="refresh" type="button">Refresh</button><a class="button" id="export" href="#">Download export</a></p>
<p class="muted" id="note"></p>
<pre id="next">Loading…</pre>
<h2>Queued (pending) reports</h2><pre id="pending">Loading…</pre>
</main><script>
(function(){
var base="/cloud/api/v1";var org=null;
function el(id){return document.getElementById(id)}
function show(id,v){el(id).textContent=typeof v==="string"?v:JSON.stringify(v,null,2)}
function get(p){return fetch(base+p,{credentials:"same-origin",headers:{accept:"application/json"}}).then(function(r){
 if(r.status===401){location.href="/login";throw new Error("login")}
 return r.json().then(function(b){if(!r.ok)throw new Error(b.message||b.error||String(r.status));return b})})}
function dl(rows){var s=el("status");s.textContent="";rows.forEach(function(r){var dt=document.createElement("dt");dt.textContent=r[0];var dd=document.createElement("dd");dd.textContent=r[1];s.appendChild(dt);s.appendChild(dd)})}
function load(){
 el("error").textContent="";
 var level=el("level").value;
 get("/organizations/"+encodeURIComponent(org)+"/telemetry").then(function(s){
  var c=s.config||{};var o=s.outbox||{};
  dl([["Level",c.level],["Transport",c.transport],["Endpoint",c.endpoint||"(none)"],["Install ID",c.installId||"(not configured)"],
   ["Digest interval",c.digestIntervalSeconds+" s"],["Probed services",(c.probes||[]).join(", ")||"(none)"],
   ["Outbox","pending "+(o.pending||0)+", sent "+(o.sent||0)+", exported "+(o.exported||0)+", dead "+(o.dead||0)],
   ["Last sent",s.lastSentAt||"never"],["Last error",s.lastError||"none"]]);
 });
 get("/organizations/"+encodeURIComponent(org)+"/telemetry/preview"+(level?"?level="+level:"")).then(function(p){
  show("note",p.note||(p.hypothetical?"Hypothetical: what would be sent at this level. Nothing changes.":""));
  show("next",p.nextDigest||"Nothing: telemetry is off.");
  if(p.pending)show("pending",p.pending.length?p.pending:"Nothing queued.");
 }).catch(function(e){el("error").textContent=e.message});
}
get("/organizations").then(function(b){var list=b.organizations||[],want=new URLSearchParams(location.search).get("organization");
 var o=want?list.filter(function(x){return x.id===want})[0]:list[0];if(!o)throw new Error(want?"Unknown organization":"No organization");org=o.id;
 el("export").href=base+"/organizations/"+encodeURIComponent(org)+"/telemetry/export?snapshot=1";load()})
 .catch(function(e){el("error").textContent=e.message});
el("refresh").addEventListener("click",load);el("level").addEventListener("change",load);
})();
</script></body></html>`;
}
