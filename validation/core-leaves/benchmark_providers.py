"""Alternating isolated runs; do not run other CPU-heavy work concurrently."""
import json,os,statistics,subprocess,sys
from pathlib import Path
base=Path(__file__).resolve().parent
updated=Path(sys.argv[1]).resolve()
old=Path(sys.argv[2]).resolve()
env=dict(os.environ,FEATHERED_BENCH_PROFILE='0')
runs={'before':[],'after':[]}
for iteration in range(3):
    for label in (('before','after') if iteration%2==0 else ('after','before')):
        output=base/f'benchmark-{label}-{iteration}.json'
        subprocess.run([sys.executable,str(base/'profile_providers.py'),str(old if label=='before' else updated),str(output)],env=env,check=True)
        runs[label].append(json.loads(output.read_text()))
for scenario in runs['before'][0]:
    expected=runs['before'][0][scenario]['result']
    # Only actual index-build diagnostics may be fewer.
    def semantic_logs(run):
        return [log for log in run['logs'] if not log.startswith(('Indexed ', 'Detected default Python ABI'))]
    events=semantic_logs(runs['before'][0][scenario])
    assert all(run[scenario]['result']==expected and semantic_logs(run[scenario])==events
               for values in runs.values() for run in values), scenario
    print(scenario, {label:statistics.median(run[scenario]['elapsed_seconds'] for run in values)
                     for label,values in runs.items()},flush=True)
print('Every full resolution result and non-index diagnostic matches.',flush=True)
(base/'benchmark-summary.json').write_text(json.dumps({scenario:{label:{
    'seconds':[run[scenario]['elapsed_seconds'] for run in values],
    'index_builds':[len(run[scenario]['index_calls']) for run in values],
    'median_seconds':statistics.median(run[scenario]['elapsed_seconds'] for run in values)}
    for label,values in runs.items()} for scenario in runs['before'][0]},indent=2)+'\n')
