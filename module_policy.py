"""RPM supplemental metadata preservation and conservative stream selection."""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def documents(data):
    import yaml
    class NoAliases(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise RuntimeError('YAML aliases are not accepted in module metadata')
            return super().compose_node(parent, index)
    try:
        rows = list(yaml.load_all(data, Loader=NoAliases))
    except (yaml.YAMLError, RecursionError) as exc:
        raise RuntimeError(f'Invalid or excessively nested module metadata: {exc}') from exc
    if any(row is not None and not isinstance(row, dict) for row in rows):
        raise RuntimeError('Invalid modulemd document')
    return [r for r in rows if r]


def load_supplemental(repo, refs, reporter, retries):
    import core
    supplemental = {}
    for kind, ref in refs.items():
        if kind == 'primary' or (kind != 'modules' and not getattr(repo, 'preserve_repository_metadata', False)):
            continue
        compressed = core.fetch_bytes(ref.url, reporter, retries=retries, repo=repo)
        if ref.checksum:
            if core._hash_bytes(compressed, ref.checksum_type).lower() != ref.checksum.lower():
                raise RuntimeError(f'{repo.name}: {kind} metadata checksum mismatch')
        elif not repo.allow_unverified_index and core.repository_verification_strategy(repo) != 'skip-provenance':
            raise RuntimeError(f'{repo.name}: {kind} metadata has no checksum')
        expanded = core.decompress_metadata(compressed, ref.url)
        if ref.open_checksum and core._hash_bytes(expanded, ref.open_checksum_type).lower() != ref.open_checksum.lower():
            raise RuntimeError(f'{repo.name}: {kind} expanded metadata checksum mismatch')
        supplemental[kind] = expanded
    repo.supplemental_metadata = supplemental
    repo.module_documents = documents(supplemental['modules']) if 'modules' in supplemental else []


def _artifact_id(package):
    return f'{package.name}-{package.epoch or "0"}:{package.version}-{package.release}.{package.arch}'


def filter_candidates(packages, inventory, architecture):
    """Use captured module state, otherwise repository defaults; never guess a stream."""
    repos = {p.repo.source_identity: p.repo for p in packages}
    docs = [d for repo in repos.values() for d in getattr(repo, 'module_documents', [])]
    if not docs:
        return packages
    defaults = {}
    streams = []
    for doc in docs:
        data = doc.get('data', {})
        if doc.get('document') == 'modulemd-defaults' and data.get('stream') is not None:
            name, stream = str(data['module']), str(data['stream'])
            if name in defaults and defaults[name] != stream:
                raise RuntimeError(f'{name}: conflicting module defaults across repositories')
            defaults[name] = stream
        elif doc.get('document') == 'modulemd':
            streams.append(data)
    states = json.loads(getattr(inventory, 'metadata', {}).get('module_states', '{}')) if inventory else {}
    active = dict(defaults)
    for name, state in states.items():
        if state.get('state') == 'disabled':
            active.pop(name, None)
        elif state.get('state') == 'enabled':
            active[name] = str(state.get('stream', ''))
    all_modular = set(); allowed = set(); active_names = set()
    context_artifacts = {}
    active_contexts = {}
    for data in streams:
        artifacts = set(data.get('artifacts', {}).get('rpms', []))
        all_modular.update(artifacts)
        name, stream = str(data['name']), str(data['stream'])
        if active.get(name) != stream or data.get('arch', architecture) != architecture:
            continue
        # Preserve all contexts for the native module solver, but refuse a build
        # that would require choosing between different runtime contexts.
        active_contexts.setdefault((name, stream), set()).add(str(data.get('context', '')))
        allowed.update(artifacts)
        context_artifacts.setdefault((name, stream), set()).update(artifacts)
    ambiguous = set()
    for key, contexts in active_contexts.items():
        if len(contexts) > 1:
            ambiguous.update(context_artifacts[key])
    allowed.difference_update(ambiguous)
    selected = []
    for pkg in packages:
        identity = _artifact_id(pkg)
        if identity in allowed:
            selected.append(pkg); active_names.add(pkg.name)
        elif identity not in all_modular:
            selected.append(pkg)
    # Match DNF's filtering of nonmodular builds whose names belong to an active stream.
    return [p for p in selected if p.name not in active_names or _artifact_id(p) in allowed
            or getattr(p.repo, 'module_hotfixes', False)]


def emit_supplemental(output, packages, reporter):
    """Keep supplemental indexes linked from repomd and covered by the bundle seal."""
    output = Path(output)
    repos = {p.repo.source_identity: p.repo for p in packages}
    grouped = {}
    for repo in repos.values():
        for kind, data in getattr(repo, 'supplemental_metadata', {}).items():
            grouped.setdefault(kind, []).append(data)
    if not grouped:
        return
    ns = 'http://linux.duke.edu/metadata/repo'
    path = output / 'repodata' / 'repomd.xml'
    tree = ET.parse(path); root = tree.getroot()
    for kind, values in grouped.items():
        values = list(dict.fromkeys(values))
        if len(values) > 1:
            if kind != 'modules':
                raise RuntimeError(f'Cannot merge {kind} from multiple RPM repositories; publish independent mirror folders')
            import yaml
            rows = [r for value in values for r in documents(value)]
            unique = {json.dumps(r, sort_keys=True, default=str): r for r in rows}
            data = yaml.safe_dump_all(list(unique.values()), sort_keys=False).encode()
        else:
            data = values[0]
        filename = hashlib.sha256(kind.encode()).hexdigest()[:16] + '.metadata.gz'
        compressed = gzip.compress(data, mtime=0)
        (path.parent / filename).write_bytes(compressed)
        entry = ET.SubElement(root, f'{{{ns}}}data', {'type': kind})
        ET.SubElement(entry, f'{{{ns}}}checksum', {'type':'sha256'}).text = hashlib.sha256(compressed).hexdigest()
        ET.SubElement(entry, f'{{{ns}}}open-checksum', {'type':'sha256'}).text = hashlib.sha256(data).hexdigest()
        ET.SubElement(entry, f'{{{ns}}}location', {'href':'repodata/' + filename})
        ET.SubElement(entry, f'{{{ns}}}size').text = str(len(compressed))
        ET.SubElement(entry, f'{{{ns}}}open-size').text = str(len(data))
    ET.register_namespace('', ns)
    tree.write(path, encoding='utf-8', xml_declaration=True)
    reporter.log('Preserved RPM supplemental metadata: ' + ', '.join(sorted(grouped)))


def validate_modular_payloads(packages, supplemental_packages):
    docs = [doc for p in list(packages) + list(supplemental_packages)
            for doc in getattr(p.repo, "module_documents", [])]
    identities = {identity for d in docs if d.get("document") == "modulemd"
                  for identity in d.get("data", {}).get("artifacts", {}).get("rpms", [])}
    for package in packages:
        if getattr(package, "modularity_label", "") and _artifact_id(package) not in identities:
            raise RuntimeError(f"{package.nevra}: modular RPM has no matching modulemd. Load its original repository metadata before rebuilding; refusing to publish an orphan modular package.")
