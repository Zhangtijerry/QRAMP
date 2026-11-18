#!/usr/bin/env python3
"""Regenerate manuscript Figure 3 from a recorded baseline CP-SAT schedule.
Requires matplotlib. Usage: python scripts/plot_review2.py --input
revision2-results/schedules/baseline/cpsat-1.json --out Figure3_recomputed.png
"""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
p=argparse.ArgumentParser(__doc__);p.add_argument('--input',default='revision2-results/schedules/baseline/cpsat-1.json');p.add_argument('--out',default='Figure3_recomputed.png');args=p.parse_args()
tasks=json.loads(Path(args.input).read_text())['schedule'];by={x['id']:x for x in tasks};pairs=[]
for t in tasks:
 if len(t['prerequisites'])==1:pairs.append((by[t['prerequisites'][0]],t))
pairs.sort(key=lambda pair:pair[1]['start_month']+pair[1]['duration_months'])
sel=[pairs[0],pairs[len(pairs)//3],pairs[2*len(pairs)//3],pairs[-1]]
fig,ax=plt.subplots(figsize=(9.3,4.1));green='#008000';labels=[]
for k,(a,b) in enumerate(sel):
 for j,t in enumerate((a,b)):
  y=7-(2*k+j);ax.barh(y,t['duration_months'],left=t['start_month'],height=.56,color=green,alpha=.4 if j==0 else .88,edgecolor=green)
  labels.append((y,t['target_algorithm'].upper()+' '+t['type']))
 ya=7-2*k;yb=ya-1
 ax.annotate('',xy=(b['start_month'],yb),xytext=(a['start_month']+a['duration_months'],ya),arrowprops={'arrowstyle':'->','color':green,'lw':1,'connectionstyle':'angle,angleA=0,angleB=90,rad=3'})
ax.set_yticks([x[0] for x in labels],[x[1] for x in labels],fontsize=9,color=green);ax.set_xlabel('Start month',color=green);ax.set_xlim(0,46);ax.set_ylim(-.6,8.3);ax.set_xticks(range(0,46,5));ax.tick_params(colors=green);ax.axvline(36,ls='--',color=green,lw=1);ax.text(36.4,7.8,'36-month horizon',color=green,fontsize=9);ax.grid(axis='x',color='#ccdccc',lw=.5);ax.set_axisbelow(True)
for sp in ax.spines.values():sp.set_color(green)
fig.tight_layout();Path(args.out).parent.mkdir(parents=True,exist_ok=True);fig.savefig(args.out,dpi=220,bbox_inches='tight');plt.close(fig)
