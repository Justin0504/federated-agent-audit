"""Self-contained HTML dashboard for the A2A privacy demo (no build step)."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — A2A privacy audit</title>
<style>
:root{
 --bg:#0b0c0e; --surface:#131417; --surface2:#171a1f; --line:#232730;
 --ink:#e9ecf1; --ink2:#9aa3b2; --faint:#5b6473;
 --accent:#6d7dff; --accent-dim:#38406b; --danger:#ff5d6c; --ok:#3ddc84;
 --mono:"SF Mono",ui-monospace,"JetBrains Mono",Menlo,monospace;
 --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
}
:root[data-t="light"]{
 --bg:#f7f7f5; --surface:#ffffff; --surface2:#fbfbfa; --line:#e7e7e3;
 --ink:#15161a; --ink2:#565a63; --faint:#8b8f98; --accent-dim:#e5e8ff;
}
*{box-sizing:border-box}
html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
 font-size:14px;line-height:1.55;letter-spacing:-0.01em}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
header{border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;
 background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(10px)}
.hd{display:flex;align-items:center;justify-content:space-between;height:56px}
.brand{display:flex;align-items:center;gap:9px;font-weight:600;letter-spacing:-0.02em}
.dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 20%,transparent)}
.brand small{color:var(--faint);font-family:var(--mono);font-size:11px;font-weight:400;letter-spacing:0}
.iconbtn{cursor:pointer;background:transparent;border:1px solid var(--line);color:var(--ink2);
 border-radius:8px;height:32px;padding:0 11px;font-size:12.5px;display:inline-flex;align-items:center;gap:6px;
 transition:.15s}
.iconbtn:hover{border-color:var(--accent-dim);color:var(--ink)}
.hero{padding:40px 0 26px}
.hero h1{font-size:27px;line-height:1.15;margin:0 0 9px;font-weight:640;letter-spacing:-0.03em;max-width:640px}
.hero p{color:var(--ink2);margin:0;max-width:560px}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:22px 0 6px}
.seg{display:inline-flex;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:3px;gap:2px}
.seg button{cursor:pointer;background:transparent;border:0;color:var(--ink2);font:inherit;font-size:13px;
 padding:6px 13px;border-radius:7px;transition:.14s;letter-spacing:-0.01em}
.seg button:hover{color:var(--ink)}
.seg button.on{background:var(--accent-dim);color:var(--ink)}
.act{cursor:pointer;border:1px solid var(--line);background:var(--surface);color:var(--ink);
 border-radius:9px;height:34px;padding:0 14px;font:inherit;font-size:13px;display:inline-flex;align-items:center;gap:7px;transition:.15s}
.act:hover{border-color:var(--accent-dim)}
.act.primary{border-color:transparent;background:var(--accent);color:#fff}
.act.primary:hover{filter:brightness(1.08)}
.act.ghost{color:var(--ink2)}
.err{color:var(--danger);font-size:12.5px}
#byop{margin-top:12px;display:none}
textarea{width:100%;height:150px;background:var(--surface);color:var(--ink);border:1px solid var(--line);
 border-radius:10px;padding:13px;font-family:var(--mono);font-size:12.5px;line-height:1.6;resize:vertical}
textarea:focus{outline:0;border-color:var(--accent-dim)}
#out{display:none;padding-bottom:64px}
.title{display:flex;align-items:baseline;gap:12px;margin:26px 0 3px}
.title h2{font-size:17px;font-weight:600;margin:0;letter-spacing:-0.02em}
.blurb{color:var(--ink2);margin:0 0 16px;max-width:640px}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:14px}
.graph{padding:6px 4px}
.node rect{fill:var(--surface2);stroke:var(--line)}
.node text{fill:var(--ink);font-size:11.5px;font-family:var(--mono);letter-spacing:-0.02em}
.edge{fill:none;stroke:var(--accent);stroke-width:1.75;stroke-dasharray:5 5;animation:flow 1s linear infinite;opacity:.9}
.edge.bad{stroke:var(--danger)}
@keyframes flow{to{stroke-dashoffset:-20}}
.elabel{fill:var(--faint);font-size:10px;font-family:var(--mono)}
.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:14px}
.sect{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;letter-spacing:.12em;
 color:var(--faint);padding:12px 15px 0}
.card{border-bottom:1px solid var(--line);padding:13px 15px;opacity:0;transform:translateY(4px);animation:in .3s forwards}
.card:last-child{border-bottom:0}
@keyframes in{to{opacity:1;transform:none}}
.route{display:flex;align-items:center;gap:7px;font-family:var(--mono);font-size:12px;color:var(--ink2)}
.route b{color:var(--accent);font-weight:500}
.route .warn{color:var(--danger)}
.msg{margin:8px 0;color:var(--ink)}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:2px}
.chip{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:6px;background:var(--surface2);
 border:1px solid var(--line);color:var(--ink2)}
.chip.inf{border-color:var(--accent-dim);color:var(--accent)}
.lock{display:flex;align-items:center;gap:6px;color:var(--ok);font-size:11.5px;margin-top:8px}
.cv{font-family:var(--mono);font-size:11.5px;color:var(--ink2);line-height:1.7}
.cv .h{color:var(--faint)}
.viol{border-left:2px solid var(--danger)}
.viol .t{font-family:var(--mono);font-size:12px;color:var(--danger);font-weight:500}
.viol .d{color:var(--ink2);font-size:12.5px;margin-top:4px}
.none{color:var(--faint);font-size:13px;padding:13px 15px}
.badge{display:inline-flex;align-items:center;gap:8px;margin:12px 15px 15px;padding:9px 13px;border-radius:9px;
 background:color-mix(in srgb,var(--ok) 12%,transparent);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);
 font-family:var(--mono);font-size:12px}
svg.i{width:14px;height:14px;flex:none}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
</style></head><body>
<header><div class="wrap hd">
 <div class="brand"><span class="dot"></span>Sentinel <small>a2a.privacy/v1</small></div>
 <button class="iconbtn" id="theme"><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3v2M12 19v2M5 12H3M21 12h-2M6 6l1.5 1.5M16.5 16.5 18 18M18 6l-1.5 1.5M7.5 16.5 6 18"/><circle cx="12" cy="12" r="4"/></svg>theme</button>
</div></header>
<div class="wrap">
 <div class="hero">
  <h1>See cross-agent data leaks — without the auditor ever seeing the data.</h1>
  <p>A federated, center-blind auditor for multi-tenant agent systems. Content is
   hashed at the edge; only governance metadata crosses to the center.</p>
  <div class="controls">
   <div class="seg" id="scn"></div>
   <button class="act primary" id="live"><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 3l14 9-14 9V3z"/></svg>run live · real LLM</button>
   <button class="act ghost" id="byo">bring your own trace</button>
   <span class="err" id="lerr"></span>
  </div>
  <div id="byop">
   <textarea id="ta" spellcheck="false"></textarea>
   <div style="margin-top:9px;display:flex;gap:9px;align-items:center">
    <button class="act" id="runc">run audit</button><span class="err" id="cerr"></span></div>
  </div>
 </div>
 <div id="out">
  <div class="title"><h2 id="title"></h2></div>
  <p class="blurb" id="blurb"></p>
  <div class="panel graph"><svg id="svg" width="100%" viewBox="0 0 760 190"></svg></div>
  <div class="grid">
   <div class="panel"><div class="sect">exchanged between agents · stays at the edge</div><div id="hops"></div></div>
   <div>
    <div class="panel"><div class="sect">what the center sees</div><div id="cv"></div></div>
    <div class="panel" style="margin-top:14px"><div class="sect">violations</div><div id="viol"></div><div id="badge"></div></div>
   </div>
  </div>
 </div>
</div>
<script>
const NS="http://www.w3.org/2000/svg";
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e};
const S=(t,a)=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e};
const LOCK='<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';
const CHK='<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>';
const T=document.documentElement;
document.getElementById('theme').onclick=()=>T.dataset.t=T.dataset.t==='light'?'':'light';
const EX={clearances:{ads:["vendor:adtech",["marketing"]]},hops:[{from_agent:"app",to_agent:"ads",
 from_principal:"org:acme",to_principal:"vendor:adtech",text:"User u123 (a@b.com) diagnosed with diabetes; balance $4,200.",
 data_subject:"user:u123",owning_principal:"org:acme",purpose:["support"],allowed_recipients:["org:acme"]}]};
document.getElementById('ta').value=JSON.stringify(EX,null,2);
document.getElementById('byo').onclick=()=>{const p=document.getElementById('byop');p.style.display=p.style.display==='block'?'none':'block'};
document.getElementById('runc').onclick=async()=>{const err=document.getElementById('cerr');err.textContent='';
 let b;try{b=JSON.parse(document.getElementById('ta').value)}catch(e){err.textContent='invalid JSON';return}
 const d=await(await fetch('api/v1/a2a/demo/audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})).json();
 if(d.error){err.textContent=d.error;return}render(d);document.getElementById('out').scrollIntoView({behavior:'smooth'})};
document.getElementById('live').onclick=async()=>{const b=document.getElementById('live'),err=document.getElementById('lerr');err.textContent='';
 const o=b.innerHTML;b.innerHTML='running…';b.disabled=true;
 try{const d=await(await fetch('api/v1/a2a/demo/live')).json();if(d.error)err.textContent=d.error;else{render(d);document.getElementById('out').scrollIntoView({behavior:'smooth'})}}
 finally{b.innerHTML=o;b.disabled=false}};
async function load(){const s=await(await fetch('api/v1/a2a/demo/list')).json();const box=document.getElementById('scn');
 s.forEach((x,i)=>{const b=E('button',i===0?'on':'',x.title.split('—')[0].trim());b.title=x.blurb;
  b.onclick=()=>{[...box.children].forEach(c=>c.classList.remove('on'));b.classList.add('on');run(x.id)};box.appendChild(b)})}
function drawGraph(hops){const svg=document.getElementById('svg');svg.innerHTML='';
 const order=[];hops.forEach(h=>[h.from_principal,h.to_principal].forEach(p=>{if(!order.includes(p))order.push(p)}));
 const W=760,pad=76,y=95,gap=(W-2*pad)/Math.max(1,order.length-1),pos={};
 order.forEach((p,i)=>pos[p]=order.length===1?W/2:pad+i*gap);const seen={};
 hops.forEach((h,i)=>{const x1=pos[h.from_principal],x2=pos[h.to_principal],key=h.from_principal+'>'+h.to_principal;
  seen[key]=(seen[key]||0)+1;const dir=x2>=x1?1:-1,bend=(26+16*(seen[key]-1))*dir,mx=(x1+x2)/2,my=y-bend;
  const pa=S('path',{d:`M ${x1} ${y} Q ${mx} ${my} ${x2} ${y}`,class:'edge'+(h.flagged?' bad':'')});
  pa.style.animationDelay=(i*.1)+'s';svg.appendChild(pa);
  const tl=S('text',{x:mx,y:my-5,'text-anchor':'middle',class:'elabel'});tl.textContent='hop '+(i+1);svg.appendChild(tl)});
 order.forEach(p=>{const x=pos[p],w=Math.max(80,p.length*7+22),g=S('g',{class:'node'});
  g.appendChild(S('rect',{x:x-w/2,y:y-14,width:w,height:28,rx:8}));
  const t=S('text',{x:x,y:y+4,'text-anchor':'middle'});t.textContent=p;g.appendChild(t);svg.appendChild(g)})}
async function run(id){render(await(await fetch('api/v1/a2a/demo/run/'+id)).json())}
function render(d){document.getElementById('out').style.display='block';
 document.getElementById('title').textContent=d.title;document.getElementById('blurb').textContent=d.blurb;
 drawGraph(d.hops);const hops=document.getElementById('hops');hops.innerHTML='';
 d.hops.forEach((h,i)=>{const c=E('div','card');c.style.animationDelay=(i*.1)+'s';
  const tags=[...h.label.category.map(x=>`<span class="chip">${x}</span>`),
   ...h.label.inferred_categories.map(x=>`<span class="chip inf">infers ${x}</span>`)].join('');
  c.innerHTML=`<div class="route"><b>${h.from_principal}</b> → <b>${h.to_principal}</b>${h.flagged?' <span class="warn">flagged</span>':''}</div>
   <div class="msg">${h.text}</div><div class="tags">${tags||'<span class="chip">benign</span>'}<span class="chip">sens ${h.label.sensitivity}/5</span></div>
   <div class="lock">${LOCK} content hashed locally — never sent to the center</div>`;hops.appendChild(c)});
 const cv=document.getElementById('cv');cv.innerHTML='';
 d.center_view.forEach((e,i)=>{const c=E('div','card');c.style.animationDelay=(.25+i*.1)+'s';
  c.innerHTML=`<div class="cv"><span class="h">${e.from} → ${e.to}</span><br>hash=${e.hash} · ${e.category.join(',')||'—'} · sens ${e.sensitivity}</div>`;cv.appendChild(c)});
 const v=document.getElementById('viol');v.innerHTML='';
 if(d.violations.length)d.violations.forEach((x,i)=>{const c=E('div','card viol');c.style.animationDelay=(.4+i*.1)+'s';
  c.innerHTML=`<div class="t">${x.type}</div><div class="d">${x.detail}</div>`;v.appendChild(c)});
 else v.innerHTML='<div class="none">no violation</div>';
 document.getElementById('badge').innerHTML=`<div class="badge">${CHK} ${d.raw_leaks} content bytes reached the center</div>`}
load();
</script></body></html>"""
