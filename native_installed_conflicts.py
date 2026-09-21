"""Compare captured installed conflicts with native APT simulation."""
from __future__ import annotations

import json
import os
import subprocess

import apt_core as apt
import core
import inventory_relationships
import repository_tools


def run_apt_conflict_conformance(root, make_deb):
    scenarios = [('conflicts', False), ('conflicts', True), ('breaks', False), ('breaks', True)]
    for index, (field, reverse) in enumerate(scenarios):
        case = root / f'installed-conflict-{index}'
        upstream = case / 'upstream'; upstream.mkdir(parents=True)
        name, guard = 'fic-app', 'fic-installed'
        make_deb(case, upstream, name, **{field: '' if reverse else guard})
        repository_tools.rebuild_repository_metadata(upstream)
        repo = core.RepoSpec('conflict fixture', upstream.as_uri(), repo_format='apt', suite='feathered',
                            components='main', verification_strategy='skip-provenance')
        reporter = core.Reporter()
        packages = apt.load_repository(repo, {'amd64'}, reporter)
        row = {'Package': guard, 'Architecture': 'amd64', 'Version': '1.0'}
        if reverse:
            row[field.capitalize()] = name
        inv = apt.AptTargetInventory(packages={(guard, 'amd64'): '1.0'}, metadata={'relationships': 'complete'})
        inventory_relationships.attach(inv, 'DETAIL|' + json.dumps(row), 'deb')
        options = core.BuildOptions(target_inventory=inv)
        result = apt.resolve([(name, None, None)], packages, 'amd64', options, reporter)
        label = f'{"installed" if reverse else "selected"} declares {field}'
        if not result.conflicts:
            raise RuntimeError(f'[{label}] Feathered missed an installed-package conflict')
        # Emit the same package without the inventory solely to ask APT to reject
        # the independently described installed state. This is a negative fixture.
        neutral = apt.resolve([(name, None, None)], packages, 'amd64', core.BuildOptions(), reporter)
        bundle = case / 'bundle'
        apt.write_bundle(neutral, bundle, core.BuildOptions(), reporter, {'test': label})
        status = (f'Package: {guard}\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n'
                  + (f'{field.capitalize()}: {name}\n' if reverse else '')
                  + 'Description: installed conflict fixture\n\n')
        status_file = case / 'status'
        status_file.write_text(status, encoding='utf-8')
        payloads = list((bundle / 'debs').glob('*.deb'))
        if len(payloads) != 1:
            raise RuntimeError(f'[{label}] Expected one published Debian fixture')
        command = ['apt-get', '--simulate', '--no-remove',
                   '-o', f'Dir::State::status={status_file}',
                   '-o', 'Dir::Etc::sourcelist=/dev/null', '-o', 'Dir::Etc::sourceparts=-',
                   '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
                   'install', str(payloads[0])]
        solve = subprocess.run(command, capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
        output = solve.stdout + solve.stderr
        if solve.returncode == 0 or guard not in output or not any(
                word in output.lower() for word in ('remove', 'conflict', 'breaks')):
            raise RuntimeError(f'[{label}] Native APT did not reject the installed conflict:\n{output}')
        print(f'APT installed conflict {label}: PASS', flush=True)
    return f'{len(scenarios)} installed conflict scenarios passed'
