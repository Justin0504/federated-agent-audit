"""Frozen numeric evidence only. Case selection is descriptive and post hoc."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle
from build import LABELS

ROOT = Path(__file__).resolve().parents[3]
D = json.loads((ROOT/'benchmarks/multiagent_sandbox/campaign/evidence/formal-v31/task_matrix.json').read_text())
rows = D['rows']; arms = list(LABELS)
assert D['complete'] and len(rows) == 256
assert {(r['task_index'], r['arm']) for r in rows} == {(i, a) for i in range(1,33) for a in arms}
assert all(type(r[k]) is bool for r in rows for k in ('utility','attacked','budget_exhausted'))
assert all(type(r['attack_success']) is bool for r in rows if r['attacked'])
lookup = {(r['task_index'],r['arm']):r for r in rows}
# Verify task-level export against the independently computed aggregate.
agg=json.loads((ROOT/'benchmarks/multiagent_sandbox/campaign/evidence/formal-v31/paired_analysis.json').read_text())
for a in arms:
 rr=[r for r in rows if r['arm']==a]
 assert sum(r['utility'] for r in rr)==agg['methods'][a]['metrics']['all/utility']['successes']
 assert sum(r['attack_success'] for r in rr if r['attacked'])==agg['methods'][a]['metrics']['attacked/attack_success']['successes']
 assert sum(r['calls'] for r in rr)==agg['methods'][a]['cost']['model_calls']
case=min(r['task_index'] for r in rows if r['arm']=='no_gate' and r['attacked'] and r['attack_success'])
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'pdf.fonttype':42,'svg.fonttype':'none'})
OUT=Path(__file__).parent
ink='#26323B'; red='#B64E39'; green='#477969'; gray='#E6E8EA'; amber='#AA752D'
def save(fig,name):
 for ext in ('pdf','svg','png'): fig.savefig(OUT/f'{name}.{ext}',dpi=220,facecolor='white')
 plt.close(fig)
def card(ax,x,y,w,h,fc='white',ec='#CCD1D4'):
 ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.008,rounding_size=0.012',facecolor=fc,edgecolor=ec,lw=.8))
def robot(ax,x,y,color):
 card(ax,x,y,.036,.047,'white',color)
 ax.plot([x+.018,x+.018],[y+.047,y+.059],color=color,lw=1)
 for dx in (.010,.027): ax.add_patch(Circle((x+dx,y+.028),.0035,color=color))
 ax.plot([x+.011,x+.026],[y+.012,y+.012],color=color,lw=1)
fig,ax=plt.subplots(figsize=(11.4,5.6)); ax.set(xlim=(0,1),ylim=(0,1)); ax.axis('off')
ax.text(.02,.96,'ONE TASK. EIGHT EXECUTIONS.',weight='bold',fontsize=15,color=ink)
ax.text(.02,.915,f'Frozen task T{case:02d}  |  Qwen2.5-14B Q4_K_M  |  identical request, attack and budgets',fontsize=9,color='#59666F')
for i,(title,sub) in enumerate([('Task + injected input','Same task in every arm'),('Eight execution policies','12 calls / 12 actions'),('Independent native checks','Task completion + attack outcome')]):
 x=.025+i*.325; card(ax,x,.77,.30,.105,'#F5F3EF')
 if i==1: robot(ax,x+.012,.79,ink)
 elif i==0:
  card(ax,x+.015,.79,.033,.060,'white',ink)
  for yy in (.805,.820,.835): ax.plot([x+.021,x+.042],[yy,yy],color=ink,lw=.9)
 else:
  ax.add_patch(Circle((x+.032,.82),.026,facecolor='white',edgecolor=green,lw=1.4))
  ax.plot([x+.018,x+.028,x+.046],[.819,.807,.837],color=green,lw=1.8)
 ax.text(x+.063,.835,title,fontsize=9,weight='bold',color=ink)
 ax.text(x+.063,.797,sub,fontsize=8,color='#59666F')
 if i<2: ax.annotate('',xy=(x+.322,.82),xytext=(x+.30,.82),arrowprops=dict(arrowstyle='->',color=ink))
for i,a in enumerate(arms):
 x=.025+(i%4)*.245; y=.43-(i//4)*.29; r=lookup[case,a]
 color=red if r['attack_success'] else green if r['utility'] else amber
 card(ax,x,y,.225,.25,'#FBFAF7')
 ax.text(x+.012,y+.212,LABELS[a],fontsize=9,weight='bold',color=ink)
 ax.plot([x+.012,x+.21],[y+.188,y+.188],color=color,lw=2)
 ax.text(x+.012,y+.153,'TASK',fontsize=7,color='#69757D')
 ax.text(x+.21,y+.153,'DONE' if r['utility'] else 'FAILED',ha='right',fontsize=9,weight='bold',color=green if r['utility'] else red)
 ax.text(x+.012,y+.110,'NATIVE ATTACK',fontsize=7,color='#69757D')
 ax.text(x+.21,y+.110,'SUCCEEDED' if r['attack_success'] else 'NOT OBSERVED',ha='right',fontsize=8,weight='bold',color=red if r['attack_success'] else ink)
 ax.text(x+.012,y+.065,f"{r['calls']} calls   /   {r['repairs']} repairs",fontsize=9,color=ink)
 ax.text(x+.012,y+.022,'Budget exhausted' if r['budget_exhausted'] else 'Within call/action budget',fontsize=7,color=amber if r['budget_exhausted'] else '#69757D')
ax.text(.025,.067,'Zero observed attack does not imply a completed task.',weight='bold',fontsize=11,color=ink)
ax.text(.025,.027,'Post-hoc diagnostic case: first task index with ungated native attack success. All 32 tasks appear in the appendix.',fontsize=8,color='#59666F')
fig.subplots_adjust(left=.01,right=.99,bottom=.01,top=.99); save(fig,'same_task_eight_outcomes')
fig,ax=plt.subplots(figsize=(11.4,10.6))
ax.set(xlim=(-1.3,8),ylim=(33.2,-2.5)); ax.axis('off')
ax.text(-1.23,-1.95,'ALL TASKS. ALL METHODS.',fontsize=15,weight='bold',color=ink)
ax.text(-1.23,-1.2,'Cell color = native outcome; number = model calls; dot = budget exhausted. C: no attack trial; A: attacked.',fontsize=9,color='#59666F')
short=['No gate','Gate','Scope','Receipt','Deny egress','Tool Filter','IPIGuard','Filter + resume']
for j,s in enumerate(short): ax.text(j+.46,-.25,s,ha='center',fontsize=8,weight='bold')
for i in range(1,33):
 r=lookup[i,'no_gate']; ax.text(-1.15,i-.35,f"T{i:02d}  {'A' if r['attacked'] else 'C'}",va='center',fontsize=8,weight='bold' if i==case else 'normal')
 for j,a in enumerate(arms):
  r=lookup[i,a]; c=red if r['attack_success'] else green if r['utility'] else gray
  ax.add_patch(FancyBboxPatch((j+.05,i-.75),.84,.8,boxstyle='round,pad=0.01,rounding_size=0.06',facecolor=c,edgecolor='white'))
  ax.text(j+.47,i-.35,str(r['calls']),ha='center',va='center',fontsize=8,color='white' if c!=gray else ink)
  if r['budget_exhausted']: ax.plot(j+.80,i-.60,'o',ms=3,color='#171E24')
for j,(s,c) in enumerate([('Task done; no native attack',green),('Task failed; no native attack',gray),('Native attack succeeded',red)]):
 ax.plot(-1.1+j*3.0,32.75,'s',color=c,ms=9); ax.text(-.93+j*3.0,32.75,s,fontsize=8,va='center')
fig.subplots_adjust(left=.02,right=.99,top=.99,bottom=.02); save(fig,'complete_task_matrix')
(OUT/'demonstration_selection.json').write_text(json.dumps({'task_index':case,'selection':'Post-hoc: smallest stable task index with ungated native attack success','matrix_cells':256,'aggregate_counts_verified':True},indent=2)+'\n')
