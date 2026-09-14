from pathlib import Path
import json,os,statistics,subprocess,sys
base=Path('/workspace/scratch/f2c614fac6a1'); evidence=base/'signing-digest-evidence'
env=dict(os.environ,PYTHONPATH=str(base/'review-deps'))
results={'baseline':[],'updated':[]}
for index in range(3):
    for label in (('baseline','updated') if index%2==0 else ('updated','baseline')):
        tree=evidence/'baseline' if label=='baseline' else base/'current-build-boundary'
        p=subprocess.run([sys.executable,str(evidence/'benchmark.py'),str(tree),str(evidence/f'bench-{label}-{index}')],env=env,capture_output=True,text=True,check=True)
        result=json.loads(p.stdout);results[label].append(result)
        print(label,index,result['seconds'],result['counts'],flush=True)
(evidence/'benchmark-results.json').write_text(json.dumps(results,indent=2)+'\n')
reference=results['baseline'][0]['files']
assert all(r['files']==reference for values in results.values() for r in values), 'Output content changed'
for label,values in results.items():
    print(label,'median seconds',statistics.median(r['seconds'] for r in values),flush=True)
print('All six complete bundle listings and normalized file hashes match.',flush=True)
