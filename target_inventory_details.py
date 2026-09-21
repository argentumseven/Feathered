"""Capture native relationships and module/managed-package state as JSON lines.

Invoked by target_inventory.sh; stdout is appended only if collection succeeds.
"""
from __future__ import annotations
import configparser
import json
from pathlib import Path
import subprocess
import sys


def query(args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def collect(family):
    rows = []
    if family == 'deb':
        fields = ['db:Status-Abbrev', 'Package', 'Version', 'Architecture', 'Depends', 'Pre-Depends', 'Provides', 'Multi-Arch', 'Conflicts', 'Breaks']
        raw = query(['dpkg-query', '-W', '-f=' + '\t'.join('${'+f+'}' for f in fields) + '\n'])
        for line in raw.splitlines():
            values = line.split('\t')
            if values[0][:2] in {'ii', 'hi'}:
                rows.append(dict(zip(fields[1:], values[1:])))
    elif family == 'arch':
        dbpath = query(['pacman-conf', 'DBPath']).strip()
        managed = set(query(['pacman', '-Qnq']).splitlines())
        for desc in sorted((Path(dbpath) / 'local').glob('*/desc')):
            row = {}; key = None
            for line in desc.read_text(encoding='utf-8').splitlines():
                if line.startswith('%') and line.endswith('%'):
                    key = line.strip('%'); row[key] = []
                elif line and key:
                    row[key].append(line)
            if 'NAME' in row:
                row['managed'] = row['NAME'][0] in managed
                rows.append(row)
        snapshot = dict(line.split() for line in query(['pacman', '-Q']).splitlines())
        if {r['NAME'][0]: r['VERSION'][0] for r in rows} != snapshot:
            raise RuntimeError('pacman database changed during capture; retry inventory collection')
    elif family == 'rpm':
        # RPM emits dependency strings using its native formatter, including rich relations.
        fmt = 'PKG\t%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n[REQ\t%{REQUIRENAME}\t%{REQUIREFLAGS:depflags}\t%{REQUIREVERSION}\n][CON\t%{CONFLICTNAME}\t%{CONFLICTFLAGS:depflags}\t%{CONFLICTVERSION}\n][FILE\t%{FILENAMES}\n]'
        current = None
        for line in query(['rpm', '-qa', '--qf', fmt]).splitlines():
            values = line.split('\t')
            if values[0] == 'PKG':
                current = dict(zip(['name','epoch','version','release','arch'], values[1:])); current['requires'] = []; current['conflicts'] = []; current['files'] = []; rows.append(current)
            elif values[0] == 'REQ' and current is not None:
                current['requires'].append(values[1:])
            elif values[0] == 'CON' and current is not None:
                current['conflicts'].append(values[1:])
            elif values[0] == 'FILE' and current is not None:
                current['files'].append(values[1])
        states = {}
        for path in sorted(Path('/etc/dnf/modules.d').glob('*.module')):
            parser = configparser.ConfigParser(interpolation=None); parser.read(path)
            for section in parser.sections():
                states[section] = dict(parser[section])
        print('META|module_states|' + json.dumps(states, separators=(',', ':')))
    for row in rows:
        print('DETAIL|' + json.dumps(row, separators=(',', ':')))
    print('META|relationships|complete')
    print('META|conflicts|complete')


if __name__ == '__main__':
    collect(sys.argv[1])
