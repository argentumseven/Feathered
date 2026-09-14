"""Actual unsigned APT writer: 8 x 64 MiB synthetic payloads, metadata disabled.

Run in isolated processes with a supplied source tree. Fixture generation is
outside timing; cache population, staging, hashing and publication are included.
"""
from datetime import datetime
import hashlib,json,shutil,sys,time
from pathlib import Path
root=Path(sys.argv[1]).resolve(); sys.path.insert(0,str(root))
import core,apt_core,provenance
base=Path(sys.argv[2]).resolve(); base.mkdir(parents=True,exist_ok=False)
class FrozenDateTime(datetime):
    @classmethod
    def now(cls,tz=None): return cls(2020,1,2,3,4,5,tzinfo=tz)
provenance.datetime=FrozenDateTime
source=base/'source';source.mkdir()
repo=core.RepoSpec('Benchmark',source.as_uri()+'/',repo_format='apt',suite='fixture',allow_unverified_index=True)
packages=[]
for index in range(8):
    name=f'payload-{index}';path=source/(name+'.deb');h=hashlib.sha256()
    block=bytes([index+1])*(1024*1024)
    with path.open('wb') as f:
        for _ in range(64): f.write(block);h.update(block)
    packages.append(apt_core.DebPackage(name,'amd64','1.2-3',path.name,'sha256',h.hexdigest(),repo,size=path.stat().st_size))
result=apt_core.DebResolutionResult(packages,[],packages,reasons={p.nevra:'requested' for p in packages})
counts={'verification_bytes':0,'output_bytes':0,'verification_reads':0,'output_reads':0}
verify=core.hash_file;output=core.sha256_file

def counted_verify(path,algo):
    counts['verification_bytes']+=path.stat().st_size;counts['verification_reads']+=1
    return verify(path,algo)
def counted_output(path):
    counts['output_bytes']+=path.stat().st_size;counts['output_reads']+=1
    return output(path)
core.hash_file=counted_verify;core.sha256_file=counted_output;apt_core.sha256_file=counted_output
started=time.perf_counter()
apt_core.write_bundle(result,base/'bundle',core.BuildOptions(emit_repository=False),core.Reporter(),
    {'distribution':'Fixture','release':'1','arch':'amd64','package_family':'deb','workload':'Fixture',
     'repositories':[{'name':repo.name,'url':repo.url}]})
elapsed=time.perf_counter()-started
files={}
for p in sorted((base/'bundle').rglob('*')):
    if not p.is_file(): continue
    if p.suffix=='.deb': digest=output(p)
    else:
        data=p.read_text().replace(repo.source_identity,'<SOURCE-ID>').replace(source.as_uri(),'file:///fixture/source').replace(str(base),'<ROOT>')
        digest=hashlib.sha256(data.encode()).hexdigest()
    files[p.relative_to(base/'bundle').as_posix()]=digest
print(json.dumps({'seconds':elapsed,'counts':counts,'files':files},sort_keys=True))
shutil.rmtree(base)
