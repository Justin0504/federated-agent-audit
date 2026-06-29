"""Self-contained HTML dashboard for the A2A privacy demo (no build step)."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>A2A Privacy Auditor</title>
<style>
:root{--bg:#faf6f0;--card:#fff;--ink:#2b2622;--muted:#8a7f74;--line:#ece3d8;
--accent:#b5651d;--ok:#3f7d4f;--bad:#c0392b;--hash:#6b7b8c;--node:#fff;--nodeline:#d8cdbf;}
[data-t="dark"]{--bg:#1b1916;--card:#262220;--ink:#ece5db;--muted:#9b9085;--line:#37312b;
--accent:#e08a3c;--ok:#5fb377;--bad:#e0685c;--hash:#8fa0b2;--node:#2e2925;--nodeline:#4a4239;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);transition:background .2s,color .2s;
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px}
.top{display:flex;justify-content:space-between;align-items:flex-start}
h1{font-size:25px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 22px}
.theme{cursor:pointer;background:var(--card);border:1px solid var(--line);border-radius:20px;
padding:6px 13px;color:var(--ink);font-size:13px}
.scn{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.scn button{cursor:pointer;text-align:left;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:13px 15px;max-width:330px;color:var(--ink);transition:.15s}
.scn button:hover,.scn button.on{border-color:var(--accent);transform:translateY(-1px)}
.scn b{display:block;margin-bottom:3px}.scn small{color:var(--muted)}
.graph{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:8px;margin-bottom:16px}
.node rect{fill:var(--node);stroke:var(--nodeline)}
.node text{fill:var(--ink);font-size:12px;font-weight:600}
.edge{fill:none;stroke:var(--accent);stroke-width:2.4;opacity:.85;
stroke-dasharray:6 5;animation:flow 1.1s linear infinite}
.edge.bad{stroke:var(--bad)}
@keyframes flow{to{stroke-dashoffset:-22}}
.elabel{fill:var(--muted);font-size:10.5px}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}
.col h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px;
opacity:0;transform:translateY(6px);animation:in .35s forwards}
@keyframes in{to{opacity:1;transform:none}}
.hop .route{font-weight:600;font-size:13px;color:var(--accent)}
.hop .txt{margin:7px 0;padding:9px 11px;background:var(--bg);border:1px dashed var(--line);border-radius:8px}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:12px;padding:2px 8px;border-radius:20px;background:var(--bg);border:1px solid var(--line);color:var(--muted)}
.tag.inf{border-color:var(--accent);color:var(--accent)}
.lock{font-size:12px;color:var(--ok);margin-top:6px}
.cv{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--hash)}
.viol{border-left:4px solid var(--bad)}
.viol .t{font-weight:700;color:var(--bad)}.viol .d{font-size:13px;color:var(--muted);margin-top:4px}
.badge{display:inline-block;margin-top:6px;padding:9px 14px;border-radius:10px;font-weight:700;
background:rgba(63,125,79,.13);color:var(--ok);border:1px solid var(--ok)}
.none{color:var(--muted);font-style:italic}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<div class="top"><div><h1>A2A Privacy Auditor</h1>
<p class="sub">Catch cross-agent data leaks — without the center ever seeing the data.</p></div>
<button class="theme" id="theme">◐ theme</button></div>
<div class="scn" id="scn"></div>
<div style="margin:-6px 0 18px"><button class="theme" id="byo">✎ audit your own trace</button>
<div id="byop" style="display:none;margin-top:10px">
<textarea id="ta" spellcheck="false" style="width:100%;height:150px;font:12.5px ui-monospace,Menlo,monospace;
background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:11px"></textarea>
<div style="margin-top:8px"><button class="scn-run theme" id="runc" style="border-color:var(--accent);color:var(--accent)">▶ run audit</button>
<span id="cerr" style="color:var(--bad);margin-left:10px;font-size:13px"></span></div></div></div>
<div id="out" style="display:none">
<h2 id="title" style="font-size:17px;margin:0 0 4px"></h2>
<p class="sub" id="blurb"></p>
<div class="graph"><svg id="svg" width="100%" viewBox="0 0 760 200"></svg></div>
<div class="grid">
  <div class="col"><h2>What the agents exchanged (stays at the edge)</h2><div id="hops"></div></div>
  <div class="col">
    <h2>What the center sees</h2><div id="cv"></div>
    <h2 style="margin-top:18px">Violations caught</h2><div id="viol"></div>
    <div id="badge"></div>
  </div>
</div></div>
<script>
const SVGNS="http://www.w3.org/2000/svg";
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e};
const S=(t,a)=>{const e=document.createElementNS(SVGNS,t);for(const k in a)e.setAttribute(k,a[k]);return e};
document.getElementById('theme').onclick=()=>{const b=document.body;
b.dataset.t=b.dataset.t==='dark'?'':'dark';};
async function load(){const s=await(await fetch('api/v1/a2a/demo/list')).json();
const box=document.getElementById('scn');
s.forEach(x=>{const b=E('button',null,`<b>${x.title}</b><small>${x.blurb}</small>`);
b.onclick=()=>{[...box.children].forEach(c=>c.classList.remove('on'));b.classList.add('on');run(x.id)};box.appendChild(b)});}
function drawGraph(hops){const svg=document.getElementById('svg');svg.innerHTML='';
const order=[];hops.forEach(h=>[h.from_principal,h.to_principal].forEach(p=>{if(!order.includes(p))order.push(p)}));
const W=760,pad=70,y=100,gap=(W-2*pad)/Math.max(1,order.length-1);
const pos={};order.forEach((p,i)=>pos[p]=order.length===1?W/2:pad+i*gap);
// edges (drawn first, under nodes), curved + offset per repeated pair
const seen={};
hops.forEach((h,i)=>{const x1=pos[h.from_principal],x2=pos[h.to_principal];
const key=[h.from_principal,h.to_principal].join('>');seen[key]=(seen[key]||0)+1;
const k=seen[key],dir=x2>=x1?1:-1,bend=(28+18*(k-1))*dir;
const mx=(x1+x2)/2,my=y-bend;
const path=S('path',{d:`M ${x1} ${y} Q ${mx} ${my} ${x2} ${y}`,class:'edge'+(h.flagged?' bad':'')});
path.style.animationDelay=(i*.12)+'s';svg.appendChild(path);
svg.appendChild(S('text',{x:mx,y:my-4,'text-anchor':'middle',class:'elabel'})).textContent='hop '+(i+1);});
// nodes
order.forEach(p=>{const x=pos[p],w=Math.max(74,p.length*7+18);const g=S('g',{class:'node'});
g.appendChild(S('rect',{x:x-w/2,y:y-15,width:w,height:30,rx:8}));
const t=S('text',{x:x,y:y+4,'text-anchor':'middle'});t.textContent=p;g.appendChild(t);svg.appendChild(g);});}
const EXAMPLE={clearances:{ads:["vendor:adtech",["marketing"]]},
hops:[{from_agent:"app",to_agent:"ads",from_principal:"org:acme",to_principal:"vendor:adtech",
text:"User u123 (a@b.com) diagnosed with diabetes; balance $4,200.",
data_subject:"user:u123",owning_principal:"org:acme",purpose:["support"],allowed_recipients:["org:acme"]}]};
document.getElementById('ta').value=JSON.stringify(EXAMPLE,null,2);
document.getElementById('byo').onclick=()=>{const p=document.getElementById('byop');
p.style.display=p.style.display==='none'?'block':'none';};
document.getElementById('runc').onclick=async()=>{const err=document.getElementById('cerr');err.textContent='';
let body;try{body=JSON.parse(document.getElementById('ta').value)}catch(e){err.textContent='invalid JSON';return}
const d=await(await fetch('api/v1/a2a/demo/audit',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify(body)})).json();
if(d.error){err.textContent=d.error;return}render(d);
document.getElementById('out').scrollIntoView({behavior:'smooth'});};
async function run(id){render(await(await fetch('api/v1/a2a/demo/run/'+id)).json());}
function render(d){
document.getElementById('out').style.display='block';
document.getElementById('title').textContent=d.title;
document.getElementById('blurb').textContent=d.blurb;
drawGraph(d.hops);
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
