"""Hydrate captured native relationships without importing the GUI."""
import json


def attach(inventory, text, family):
    import core
    details = [json.loads(line[len('DETAIL|'):]) for line in text.splitlines() if line.startswith('DETAIL|')]
    inventory.records = details
    inventory.relationships_complete = inventory.metadata.get('relationships') == 'complete'
    inventory.retained_packages = []
    repo = core.RepoSpec('Captured target', 'file:///captured-target/', repo_format=family)
    for row in details:
        if family == 'deb':
            import apt_core as backend
            pkg = backend.DebPackage(row['Package'], row['Architecture'], row['Version'], '', '', '', repo)
            pkg.multi_arch = row.get('Multi-Arch', '')
            pkg.depends = backend.parse_dependency_field(row.get('Depends', ''), 'depends')
            pkg.pre_depends = backend.parse_dependency_field(row.get('Pre-Depends', ''), 'pre-depends')
            pkg.conflicts = backend.parse_dependency_field(row.get('Conflicts', ''), 'conflicts')
            pkg.breaks = backend.parse_dependency_field(row.get('Breaks', ''), 'breaks')
            pkg.provides = [backend._parse_atom(x.strip()) for x in row.get('Provides', '').split(',') if x.strip()]
        elif family == 'arch':
            import arch_core as backend
            pkg = backend.ArchPackage(row['NAME'][0], row.get('ARCH', ['any'])[0], row['VERSION'][0], '', '', '', repo)
            pkg.depends = [backend.parse_relation(x) for x in row.get('DEPENDS', [])]
            pkg.provides = [backend.parse_relation(x) for x in row.get('PROVIDES', [])]
            pkg.conflicts = [backend.parse_relation(x, 'conflicts') for x in row.get('CONFLICTS', [])]
            pkg.managed = row['managed']
        else:
            pkg = core.Package(row['name'], row['arch'], row['epoch'], row['version'], row['release'], '', '', '', repo)
            pkg.files = list(row.get("files", []))
            caps = inventory.package_capabilities.get(pkg.nevra, [])
            pkg.provides = list(caps)
            for field in ('requires', 'conflicts'):
                for name, flags, evr in row.get(field, []):
                    ep, version, release = core._parse_evr_text(evr)
                    getattr(pkg, field).append(core.Requirement(name, flags or None, ep, version or None, release, field))
        inventory.retained_packages.append(pkg)
    if inventory.relationships_complete:
        packages = inventory.retained_packages
        if family == 'rpm':
            matched = {p.nevra for p in packages} == inventory.nevras
        elif family == 'deb':
            matched = {(p.name, p.arch): p.version for p in packages} == inventory.packages
        else:
            matched = {p.name: p.version for p in packages} == inventory.packages
        if not matched:
            raise RuntimeError('Target inventory relationships do not match the captured package versions. The package database may have changed during collection; collect it again.')
    return inventory
