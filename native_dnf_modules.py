"""Native DNF checks for module dependency activation and context selection."""
from __future__ import annotations

import json
import shutil
import subprocess

import core
import repository_tools


def _module(name, stream, context, package, version, requires=None):
    return {'document': 'modulemd', 'version': 2, 'data': {
        'name': name, 'stream': stream, 'version': 1, 'context': context,
        'arch': 'x86_64', 'summary': 'Feathered module fixture',
        'description': 'Controlled module dependency fixture.',
        'license': {'module': ['MIT'], 'content': ['MIT']},
        'dependencies': [{'requires': requires or {}}],
        'artifacts': {'rpms': [f'{package}-0:{version}-1.noarch']}}}


def run_modular_conformance(root, make_rpm):
    import yaml
    for tool in ('createrepo_c', 'modifyrepo_c'):
        if not shutil.which(tool):
            raise RuntimeError(f'Modular DNF conformance requires {tool}')
    fixture = root / 'modular'
    fixture.mkdir()
    payloads = fixture / 'payloads'
    payloads.mkdir()
    builds = [
        ('fnm-runtime', '1.0', '', 'runtime:stable:1:ctx9'),
        ('fnm-runtime', '2.0', '', 'runtime:next:1:ctx9'),
        ('fnm-app', '1.0', 'fnm-runtime = 1.0', 'apps:stable:1:stable9'),
        ('fnm-app', '2.0', 'fnm-runtime = 2.0', 'apps:stable:1:next9'),
        ('fnm-app', '3.0', 'fnm-runtime = 1.0', 'apps:stable:1:stable8'),
    ]
    for name, version, requires, label in builds:
        make_rpm(fixture, payloads, name, requires, version=version, modularity_label=label)
        rpm = payloads / f'{name}-{version}-1.noarch.rpm'
        tags = repository_tools._rpm_header_tags(rpm)
        if tags.get(5096) != [label]:
            raise RuntimeError(f'Modular fixture RPM has no expected modularity label: {rpm.name}')

    make_rpm(fixture, payloads, 'fnm-plain')

    runtime = _module('runtime', 'stable', 'ctx9', 'fnm-runtime', '1.0')
    runtime_next = _module('runtime', 'next', 'ctx9', 'fnm-runtime', '2.0')
    stable = _module('apps', 'stable', 'stable9', 'fnm-app', '1.0', {'runtime': ['stable'], 'platform': ['el9']})
    next_context = _module('apps', 'stable', 'next9', 'fnm-app', '2.0', {'runtime': ['next'], 'platform': ['el9']})
    other_platform = _module('apps', 'stable', 'stable8', 'fnm-app', '3.0', {'runtime': ['stable'], 'platform': ['el8']})
    default = {'document': 'modulemd-defaults', 'version': 1, 'data': {'module': 'apps', 'stream': 'stable'}}
    enabled_next = {'runtime': {'state': 'enabled', 'stream': 'next'}}
    disabled_runtime = {'runtime': {'state': 'disabled'}}
    scenarios = [
        ('dependent stream', [stable, runtime], {}, '1.0', 'fnm-app'),
        ('captured context', [stable, next_context, runtime, runtime_next], enabled_next, '2.0', 'fnm-app'),
        ('platform context', [stable, other_platform, runtime], {}, '1.0', 'fnm-app'),
        ('disabled dependency', [stable, runtime], disabled_runtime, None, 'fnm-app'),
        ('unrelated ambiguous contexts', [stable, next_context, runtime, runtime_next], {}, '1.0', 'fnm-plain'),
    ]
    for index, (label, documents, states, expected_version, root_name) in enumerate(scenarios):
        case = fixture / str(index)
        upstream = case / 'upstream'
        upstream.mkdir(parents=True)
        # Each source includes only the artifacts described by its modulemd.
        identities = {identity for doc in documents for identity in doc['data']['artifacts']['rpms']}
        for name, version, _, _ in builds:
            if f'{name}-0:{version}-1.noarch' in identities:
                filename = f'{name}-{version}-1.noarch.rpm'
                shutil.copy2(payloads / filename, upstream / filename)
        if root_name == 'fnm-plain':
            shutil.copy2(payloads / 'fnm-plain-1.0-1.noarch.rpm', upstream)
        subprocess.run(['createrepo_c', str(upstream)], check=True, capture_output=True, text=True)
        module_file = case / 'modules.yaml'
        module_file.write_text(yaml.safe_dump_all([default] + documents), encoding='utf-8')
        subprocess.run(['modifyrepo_c', '--mdtype=modules', str(module_file), str(upstream / 'repodata')],
                       check=True, capture_output=True, text=True)
        reporter = core.Reporter()
        repo = core.RepoSpec('modular fixture', upstream.resolve().as_uri(), repo_format='rpm',
                             verification_strategy='skip-provenance')
        packages = core.load_repository(repo, {'noarch', 'x86_64'}, reporter)
        inventory = core.TargetInventory(metadata={'module_states': json.dumps(states), 'platform_id': 'platform:el9'})
        options = core.BuildOptions(include_dependencies=True, emit_repository=True, target_inventory=inventory)
        try:
            result = core.resolve([(root_name, None, None)], packages, 'x86_64', options, reporter)
        except RuntimeError as exc:
            if expected_version is not None or 'No compatible module runtime dependency set' not in str(exc):
                raise
        else:
            if expected_version is None:
                raise RuntimeError(f'[{label}] Feathered accepted a disabled module dependency')
            expected = {(root_name, expected_version)}
            if root_name == 'fnm-app':
                expected.add(('fnm-runtime', expected_version))
            actual = {(p.name, p.version) for p in result.selected}
            if result.unresolved or result.conflicts or actual != expected:
                raise RuntimeError(f'[{label}] Incorrect modular closure: {actual}, {result.unresolved}, {result.conflicts}')
            bundle = case / 'bundle'
            core.write_bundle(result, bundle, options, reporter, {'test': 'native-dnf-modules:' + label})
            upstream = bundle

        installroot = case / 'installroot'
        modules = installroot / 'etc/dnf/modules.d'
        modules.mkdir(parents=True)
        for name, state in states.items():
            (modules / f'{name}.module').write_text(
                f'[{name}]\nname={name}\nstream={state.get("stream", "")}\n'
                f'state={state["state"]}\nprofiles=\n', encoding='utf-8')
        # Test the emitted bundle, including real module headers and modulemd.
        # The rejection case uses the source because no bundle should be built.
        command = ['dnf', '-y', '--installroot', str(installroot), '--releasever', '9',
                   '--setopt=reposdir=/dev/null', f'--setopt=cachedir={case / "cache"}',
                   '--setopt=persistdir=/var/lib/dnf', '--setopt=module_platform_id=platform:el9',
                   '--setopt=install_weak_deps=False', '--setopt=tsflags=test', '--disablerepo=*',
                   f'--repofrompath=feathered,{upstream.resolve().as_uri()}', '--enablerepo=feathered',
                   '--nogpgcheck', 'install', root_name if expected_version is None else f'{root_name}-{expected_version}-1.noarch']
        solve = subprocess.run(command, capture_output=True, text=True, env=_dnf_environment())
        output = solve.stdout + solve.stderr
        if expected_version is None:
            if solve.returncode == 0 or not any(word in output.lower() for word in ('modular', 'module')):
                raise RuntimeError(f'[{label}] Native DNF did not reject the disabled dependency:\n{output}')
        elif solve.returncode or any(name not in output for name, _ in expected):
            raise RuntimeError(f'[{label}] Native DNF could not test Feathered modular bundle:\n{output}')
        print(f'DNF modular {label}: PASS', flush=True)
    return f'{len(scenarios)} modular scenarios passed'


def _dnf_environment():
    import os
    return dict(os.environ, LC_ALL='C')
