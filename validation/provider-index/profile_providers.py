"""Synthetic RPM catalog; actual public transaction resolver, no network or I/O.

Usage: python profile_providers.py SOURCE_TREE REPORT_JSON [CATALOG_SIZE]
Fixture construction is excluded from timing. Report preserves full result and
operator event ordering, alongside timing of every provider-index build.
"""
import cProfile
import io
import json
import os
from pathlib import Path
import pstats
import sys
import time

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
import core

catalog_size = int(sys.argv[3]) if len(sys.argv) > 3 else 12000
repo = core.RepoSpec('Fixture', 'https://fixture.invalid/rpm/')

def package(name, version='1', requires=()):
    return core.Package(name, 'x86_64', '0', version, '1', name+'.rpm', 'sha256', '', repo,
                        provides=[core.Requirement(f'{name}-cap-{i}') for i in range(4)],
                        files=[f'/usr/share/{name}/file-{i}' for i in range(8)], requires=list(requires))

background = [package(f'catalog-{i:05d}') for i in range(catalog_size)]
results = {}
for name, roots_count, constrained in [('ordinary', 16, False), ('one-constrained-root', 1, True), ('sixteen-constrained-roots', 16, True)]:
    roots = [f'root-{i:02d}' for i in range(roots_count)]
    packages = background + [package(root, version) for root in roots for version in ['1', '2']]
    app = package('application', requires=[core.Requirement(root, 'EQ', '0', '1', '1') for root in roots] if constrained else [])
    packages.append(app)
    requests = [(root, None, None) for root in roots + ['application']]
    calls = []; logs = []
    original = core.build_provider_index
    def index(packages, reporter=None, original=original, calls=calls):
        started = time.perf_counter()
        result = original(packages, reporter)
        calls.append({'seconds':time.perf_counter()-started, 'packages':len(packages), 'keys':len(result)})
        return result
    core.build_provider_index = index
    profiler = cProfile.Profile()
    profiling = os.environ.get("FEATHERED_BENCH_PROFILE", "1") == "1"
    if profiling: profiler.enable()
    started = time.perf_counter()
    try:
        result = core.resolve(requests, packages, 'x86_64', core.BuildOptions(), core.Reporter(log=logs.append))
    finally:
        elapsed = time.perf_counter()-started; profiler.disable(); core.build_provider_index = original
    buffer = io.StringIO()
    if profiling: pstats.Stats(profiler, stream=buffer).sort_stats('cumulative').print_stats(25)
    results[name] = {'elapsed_seconds':elapsed,'index_calls':calls,'profile':buffer.getvalue(),
        'result': {'selected':[(p.nevra,p.repo.source_identity) for p in result.selected],
                   'roots':[(p.nevra,p.repo.source_identity) for p in result.roots],
                   'unresolved':[core.format_requirement(r) for r in result.unresolved],
                   'conflicts':result.conflicts,'reasons':result.reasons,
                   'unresolved_notes':result.unresolved_notes,
                   'skipped_installed':result.skipped_installed,'installed_satisfied':result.installed_satisfied},
        'logs':logs}
    print(name, f'{elapsed:.3f}s', len(calls), 'index builds', flush=True)
Path(sys.argv[2]).write_text(json.dumps(results,indent=2)+'\n')
