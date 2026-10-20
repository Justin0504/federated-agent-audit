"""Publication vector figures from saved observations; no invented data."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).parent
DATA=ROOT/'deploy/research/results'
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'pdf.fonttype':42,
                     'svg.fonttype':'none','axes.spines.top':False,'axes.spines.right':False})
INK='#26343d'; RUST='#ac4933'; OLIVE='#65783c'; SAND='#d9be82'; GREY='#71808a'


def save(fig,name):
    for ext in ['pdf','svg','png']:
        fig.savefig(OUT/f'{name}.{ext}',dpi=190,facecolor='white')
    plt.close(fig)


fig,ax=plt.subplots(figsize=(11,5.2))
ax.set(xlim=(0,11),ylim=(0,5.2));ax.axis('off')
ax.text(.15,4.95,'Observed deployment: raw data stays on the business side',fontsize=15,weight='bold',color=INK)
ax.text(.15,4.62,'Jetstream integration pilot  |  shared checkpoint, two stateless roles',color=GREY)
for x,y,w,h,color,label in [(.1,.8,7.3,3.5,'#f4f1e9','BUSINESS NETWORK'),(8,.8,2.9,3.5,'#eef0f2','AUDIT NETWORK')]:
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.03',fc=color,ec='#cbd1d4'))
    ax.text(x+.18,y+h-.3,label,fontsize=9,weight='bold',color=GREY)
def box(x,y,w,h,text,color):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.04',fc='white',ec=color,lw=1.6))
    ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=10,color=INK)
def arrow(a,b,color=GREY):
    ax.add_patch(FancyArrowPatch(a,b,arrowstyle='-|>',mutation_scale=12,lw=1.5,color=color))
box(.4,2.55,1.7,.95,'MiniLM + Qdrant\nsemantic retrieval',OLIVE)
box(2.65,2.55,1.85,.95,'PostgreSQL\ncurrent grants',RUST)
box(5.05,2.55,1.9,.95,'Qwen researcher\n→ customer reply',OLIVE)
box(2.65,1.15,1.85,.8,'Durable outbox\nsigned metadata',SAND)
box(8.35,2.55,2.15,.95,'Private FastAPI\nallow / deny / unknown',GREY)
box(8.35,1.15,2.15,.8,'Separate PostgreSQL\nevent-ID deduplication',GREY)
arrow((2.1,3),(2.65,3));arrow((4.5,3),(5.05,3));arrow((3.55,2.55),(3.55,1.95))
arrow((4.5,1.55),(8.35,3),SAND);arrow((9.4,2.55),(9.4,1.95))
ax.plot([7.7,7.7],[.6,4.35],ls='--',lw=1.6,color=RUST)
ax.text(6.15,1.22,'No raw text\nto center',ha='center',color=RUST,weight='bold')
ax.text(.15,.32,'Signed reports authenticate claims; generated-output events remain UNKNOWN without semantic evidence.',fontsize=10,color=INK)
fig.subplots_adjust(left=.01,right=.99,top=.99,bottom=.01)
save(fig,'01_deployment')

rows=[json.loads(s) for s in (DATA/'jetstream-scale-20261013/attempts.jsonl').read_text().splitlines()]
fig,axes=plt.subplots(1,2,figsize=(10.5,4.9))
for ax,metric,title in zip(axes,['unauthorized_context','false_denial'],['A  Unauthorized recipient context','B  Denied despite valid authorization']):
    cases=['revoked','deleted'] if metric=='unauthorized_context' else ['new_grant','policy_unavailable']
    for k,(strategy,color,label) in enumerate([('retrieval_snapshot',RUST,'Retrieval snapshot'),('delivery_recheck',OLIVE,'Delivery recheck')]):
        values=[]
        for case in cases:
            group=[r for r in rows if r['strategy']==strategy and r['scenario']==case]
            assert len(group)==156
            values.append(sum(r[metric] for r in group))
        xs=np.arange(2)+(k-.5)*.3
        bars=ax.bar(xs,values,width=.28,color=color,label=label)
        for b,value in zip(bars,values):
            ax.text(b.get_x()+b.get_width()/2,value+5,f'{value}/156',ha='center',fontsize=10)
    ax.set_title(title,loc='left',fontsize=12,weight='bold',pad=16)
    ax.set_xticks(range(2),[x.replace('_','\n').capitalize() for x in cases]);ax.set_ylim(0,185)
    ax.set_yticks([0,52,104,156]);ax.set_ylabel('Operations');ax.grid(axis='y',alpha=.15);ax.set_axisbelow(True)
axes[0].legend(frameon=False,loc='upper left',bbox_to_anchor=(0,-.22),ncol=2)
fig.text(.075,.045,'1,872 repeated infrastructure operations; six authored scenarios. No independent-sample confidence intervals.',fontsize=9,color=GREY)
fig.subplots_adjust(left=.075,right=.98,top=.83,bottom=.3,wspace=.33)
save(fig,'02_policy_tradeoff')

p=DATA/'live-v1-20261013/run-fb8ca6d999cb4c9fb8e8ccbf6ca4ec06'
scores=json.loads((p/'scores.json').read_text())
labels=[r['task'].replace('_',' ')+' / '+('snapshot' if r['strategy']=='retrieval_snapshot' else 'recheck') for r in scores]
values=np.array([[len(r['unauthorized_context'])>0,len(r['output_hits'])>0,r['expected_terms_present'],r['truncations']] for r in scores],float)
fig,ax=plt.subplots(figsize=(10.5,5.5))
colors=np.empty((8,4,4))
from matplotlib.colors import to_rgba
for i in range(8):
    for j in range(4):
        colors[i,j]=to_rgba(SAND if j==2 and values[i,j] else RUST if j!=2 and values[i,j] else '#eef0f2')
ax.imshow(colors,aspect='auto')
for i in range(8):
    for j in range(4):
        text=str(int(values[i,j]))+'/2' if j==3 else ('yes' if values[i,j] else 'no')
        ax.text(j,i,text,ha='center',va='center',color='white' if j!=2 and values[i,j] else INK,fontsize=11)
ax.set_xticks(range(4),['Unauthorized\ninput context','Protected marker\nin final output','Required terms\npresent (proxy)','Calls hitting\ntoken cap'])
ax.xaxis.tick_top();ax.tick_params(length=0,pad=10);ax.set_yticks(range(8),labels,fontsize=10)
for spine in ax.spines.values():spine.set_visible(False)
ax.set_xticks(np.arange(-.5,4,1),minor=True);ax.set_yticks(np.arange(-.5,8,1),minor=True);ax.grid(which='minor',color='white',lw=3)
fig.text(.05,.95,'Live pilot: reporting coverage is not semantic correctness',fontsize=15,weight='bold',color=INK)
fig.text(.05,.075,'8 episodes · 16 generations · 12 token-cap hits · 40/40 observed events received',fontsize=10,color=INK)
fig.text(.05,.035,'Keyword presence is not task success: the Birch recheck answer misattributes an Acorn tracking reference.',fontsize=9,color=GREY)
fig.subplots_adjust(left=.30,right=.98,top=.78,bottom=.14)
save(fig,'03_live_limitations')
