from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
root=Path(__file__).resolve().parents[3]
s=json.loads((root/'deploy/research/results/agentdojo-external-v1/summary.json').read_text())
out=root/'paper/figures/agentdojo20261013';out.mkdir(exist_ok=True)
modes=['no_gate','intent_only','destination_only','combined','deny_egress']
labels=['No gate','Intent only','Destination only','Intent + destination','Deny mediated egress']
colors=['#666A73','#A7663A','#647D91','#7C4F67','#B5A58A']
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'pdf.fonttype':42,'svg.fonttype':'none'})
fig,axes=plt.subplots(1,3,figsize=(10.2,3.5),sharey=True)
for ax,(group,metric,title) in zip(axes,[('attacked','attack_success','A  Attack success ↓'),('clean','utility_success','B  Clean-task completion ↑'),('attacked','utility_success','C  Attacked-task completion ↑')]):
 n=s[group]['n'];counts=[s[group]['arms'][m][metric] for m in modes];values=[100*c/n for c in counts]
 ax.barh(range(5),values,color=colors,height=.58)
 for j,(v,c) in enumerate(zip(values,counts)):
  ax.text(v+1.8 if v<75 else v-1.8,j,f'{c}/{n}'+('*' if modes[j]=='deny_egress' else ''),va='center',ha='left' if v<75 else 'right',color='#252525' if v<75 else 'white',fontsize=9)
 ax.set_xlim(0,108);ax.set_xticks([0,25,50,75,100]);ax.set_xticklabels(['0','25','50','75','100%'])
 ax.set_title(title,loc='left',fontsize=10.5,pad=12);ax.set_axisbelow(True);ax.grid(axis='x',color='#E6E2DD',lw=.6)
 ax.spines[['top','right','left']].set_visible(False);ax.spines['bottom'].set_color('#AAA39A');ax.tick_params(axis='y',length=0)
axes[0].set_yticks(range(5),labels);axes[0].invert_yaxis()
fig.subplots_adjust(left=.19,right=.985,top=.85,bottom=.18,wspace=.24)
for ext in ['pdf','svg','png']:fig.savefig(out/f'privacy_utility.{ext}',dpi=200,facecolor='white')
print(out)
