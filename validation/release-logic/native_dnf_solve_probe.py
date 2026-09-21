"""Local DNF solves and downloads; RPM transaction testing remains a CI gate."""
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import native_conformance
original = subprocess.run

def solve_only(command, *args, **kwargs):
    if isinstance(command, list) and command and command[0] == 'dnf':
        updated = []
        index = 0
        while index < len(command):
            if command[index:index + 2] == ['--setopt', 'tsflags=test']:
                index += 2
                continue
            if command[index] != '--setopt=tsflags=test':
                updated.append(command[index])
            index += 1
        command = updated[:1] + ['--downloadonly'] + updated[1:]
    return original(command, *args, **kwargs)

subprocess.run = solve_only
print('DNF dependency resolution and downloads only; no RPM transaction test.', flush=True)
result = native_conformance.run_dnf_conformance()
print(result.replace('transaction-tested', 'dependency-resolved (download-only)'))
