"""Resolve unambiguous module runtime requirements before RPM selection.

This is a bounded metadata solver. DNF still evaluates the receiver transaction.
When metadata permits different streams or contexts, require target state instead
of choosing one by repository order.
"""
from __future__ import annotations

import json


def _accepts(stream, constraints):
    values = [str(value) for value in constraints]
    included = {value for value in values if not value.startswith('-')}
    excluded = {value[1:] for value in values if value.startswith('-')}
    return (not included or stream in included) and stream not in excluded


def active_module_documents(documents, inventory, architecture):
    metadata = getattr(inventory, 'metadata', {}) if inventory else {}
    states = json.loads(metadata.get('module_states', '{}'))
    defaults = {}
    streams = []
    for document in documents:
        data = document.get('data', {})
        if document.get('document') == 'modulemd-defaults' and data.get('stream') is not None:
            name, stream = str(data['module']), str(data['stream'])
            if name in defaults and defaults[name] != stream:
                raise RuntimeError(f'{name}: conflicting module defaults across repositories')
            defaults[name] = stream
        elif document.get('document') == 'modulemd' and data.get('arch', architecture) == architecture:
            streams.append(data)

    # Old module builds remain usable RPM candidates within the chosen context.
    # Runtime constraints and demodularization come from its newest module build.
    groups = {}
    for data in streams:
        key = (str(data['name']), str(data['stream']), str(data.get('context', '')))
        groups.setdefault(key, []).append(data)
    variants = {}
    platform_streams = set()
    for (name, stream, context), rows in groups.items():
        latest = max(int(row.get('version', 0)) for row in rows)
        seen = set()
        for row in rows:
            if int(row.get('version', 0)) != latest:
                continue
            for block in row.get('dependencies', []) or [{}]:
                requires = {str(key): [str(value) for value in values]
                            for key, values in block.get('requires', {}).items()}
                identity = json.dumps(requires, sort_keys=True)
                if identity in seen:
                    continue
                seen.add(identity)
                variants.setdefault(name, []).append((stream, context, requires))
                platform_streams.update(value for value in requires.get('platform', [])
                                        if not value.startswith('-'))

    platform = metadata.get('platform_id', '')
    if platform:
        if not platform.startswith('platform:') or not platform.split(':', 1)[1]:
            raise RuntimeError('Invalid captured module platform_id; collect the target inventory again')
        platform_streams = {platform.split(':', 1)[1]}
    variants['platform'] = [(stream, '', {}) for stream in sorted(platform_streams)]
    disabled = {name for name, state in states.items() if state.get('state') == 'disabled'}
    enabled = {name: str(state.get('stream', '')) for name, state in states.items()
               if state.get('state') == 'enabled'}
    active = {name: stream for name, stream in defaults.items() if name in variants}
    active.update({name: stream for name, stream in enabled.items() if name in variants})
    active = {name: stream for name, stream in active.items() if name not in disabled}
    if not active:
        return []

    # Each stack item is one consistent partial assignment. Requirements are
    # checked again when a cycle reaches an already assigned module.
    stack = [({}, {name: [[stream]] for name, stream in active.items()})]
    solution = None
    solution_key = None
    visited = 0
    while stack:
        chosen, constraints = stack.pop()
        visited += 1
        if visited > 10000:
            raise RuntimeError('Module dependency search exceeded its limit; capture explicit target streams or narrow the repositories')
        if any(name in disabled or any(not _accepts(chosen[name][0], rule) for rule in rules)
               for name, rules in constraints.items() if name in chosen):
            continue
        pending = [name for name in constraints if name not in chosen]
        if not pending:
            key = tuple(sorted((name, variant[0], variant[1]) for name, variant in chosen.items()))
            if solution_key is not None and key != solution_key:
                differing = sorted(name for name in set(solution) | set(chosen)
                                   if (solution.get(name) or ())[:2] != (chosen.get(name) or ())[:2])
                raise RuntimeError('Ambiguous module streams or contexts: ' + ', '.join(differing)
                                   + '. Capture the target module state or narrow the source repositories.')
            solution, solution_key = chosen, key
            continue
        choices = {}
        for name in pending:
            choices[name] = [variant for variant in variants.get(name, [])
                             if name not in disabled
                             and (name not in enabled or variant[0] == enabled[name])
                             and all(_accepts(variant[0], rule) for rule in constraints[name])]
        name = min(pending, key=lambda item: (len(choices[item]), item))
        for variant in choices[name]:
            updated = {key: list(value) for key, value in constraints.items()}
            for dependency, values in variant[2].items():
                updated.setdefault(dependency, []).append(values)
            stack.append((dict(chosen, **{name: variant}), updated))
    if solution is None:
        requested = ', '.join(f'{name}:{stream}' for name, stream in sorted(active.items()))
        raise RuntimeError('No compatible module runtime dependency set for ' + requested
                           + '. Check disabled streams, dependency metadata, and the captured platform_id.')
    return [row for key, rows in groups.items()
            if key[0] in solution and key[1:] == solution[key[0]][:2] for row in rows]
