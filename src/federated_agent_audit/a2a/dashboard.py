"""Self-contained HTML dashboard for the A2A privacy demo (no build step)."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>A2A Privacy Auditor</title>
<style>
:root{--bg:#faf6f0;--card:#fff;--ink:#2b2622;--muted:#8a7f74;--line:#ece3d8;
--accent:#b5651d;--ok:#3f7d4f;--bad:#c0392b;--hash:#6b7b8c;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px}
h1{font-size:25px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 22px}
.scn{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.scn button{cursor:pointer;text-align:left;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:13px 15px;max-width:340px;transition:.15s}
.scn button:hover{border-color:var(--accent);transform:translateY(-1px)}
.scn b{display:block;margin-bottom:3px}.scn small{color:var(--muted)}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}
.col h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px;
opacity:0;transform:translateY(6px);animation:in .35s forwards}
@keyframes in{to{opacity:1;transform:none}}
.hop .route{font-weight:600;font-size:13px;color:var(--accent)}
.hop .txt{margin:7px 0;padding:9px 11px;background:#fcf9f4;border:1px dashed var(--line);border-radius:8px}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:12px;padding:2px 8px;border-radius:20px;background:#f0e7da;color:#6b5d4d}
.tag.inf{background:#fbe6d6;color:#a85318}
.lock{font-size:12px;color:var(--ok);margin-top:6px}
.cv{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--hash)}
.viol{border-left:4px solid var(--bad)}
.viol .t{font-weight:700;color:var(--bad)}.viol .d{font-size:13px;color:var(--muted);margin-top:4px}
.badge{display:inline-block;margin-top:6px;padding:9px 14px;border-radius:10px;font-weight:700;
background:#eaf5ec;color:var(--ok);border:1px solid #cfe7d4}
.none{color:var(--muted);font-style:italic}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<h1>A2A Privacy Auditor</h1>
<p class="sub">Catch cross-agent data leaks — without the center ever seeing the data.</p>
<div class="scn" id="scn"></div>
<div id="out" style="display:none">
<h2 id="title" style="font-size:17px;margin:0 0 4px"></h2>
<p class="sub" id="blurb"></p>
<div class="grid">
  <div class="col"><h2>What the agents exchanged (stays at the edge)</h2><div id="hops"></div></div>
  <div class="col">
    <h2>What the center sees</h2><div id="cv"></div>
    <h2 style="margin-top:18px">Violations caught</h2><div id="viol"></div>
    <div id="badge"></div>
  </div>
</div></div>
<script>
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e};
async function load(){const s=await(await fetch('api/v1/a2a/demo/list')).json();
const box=document.getElementById('scn');
s.forEach(x=>{const b=E('button',null,`<b>${x.title}</b><small>${x.blurb}</small>`);
b.onclick=()=>run(x.id);box.appendChild(b)});}
async function run(id){const d=await(await fetch('api/v1/a2a/demo/run/'+id)).json();
document.getElementById('out').style.display='block';
document.getElementById('title').textContent=d.title;
document.getElementById('blurb').textContent=d.blurb;
const hops=document.getElementById('hops');hops.innerHTML='';
d.hops.forEach((h,i)=>{const c=E('div','card hop');c.style.animationDelay=(i*.12)+'s';
const tags=[...h.label.category.map(x=>`<span class="tag">${x}</span>`),
...h.label.inferred_categories.map(x=>`<span class="tag inf">infers ${x}</span>`)].join('');
c.innerHTML=`<div class="route">${h.from_principal} → ${h.to_principal} ${h.flagged?'⚠️':''}</div>
<div class="txt">${h.text}</div><div class="tags">${tags||'<span class="tag">benign</span>'}
<span class="tag">sens ${h.label.sensitivity}/5</span></div>
<div class="lock">🔒 content hashed locally — never sent to the center</div>`;hops.appendChild(c)});
const cv=document.getElementById('cv');cv.innerHTML='';
d.center_view.forEach((e,i)=>{const c=E('div','card');c.style.animationDelay=(.3+i*.12)+'s';
c.innerHTML=`<div class="cv">${e.from} → ${e.to}<br>hash=${e.hash} · ${e.category.join(',')||'—'} · sens ${e.sensitivity}</div>`;cv.appendChild(c)});
const v=document.getElementById('viol');v.innerHTML='';
if(d.violations.length){d.violations.forEach((x,i)=>{const c=E('div','card viol');c.style.animationDelay=(.5+i*.12)+'s';
c.innerHTML=`<div class="t">${x.type}</div><div class="d">${x.detail}</div>`;v.appendChild(c)});}
else v.innerHTML='<p class="none">no violation</p>';
document.getElementById('badge').innerHTML=`<div class="badge">Raw content bytes reaching the center: ${d.raw_leaks} ✓</div>`;}
load();
</script></div></body></html>"""
