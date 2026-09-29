#!/usr/bin/env python3
"""Run independent suites without combining their top-level fixture modules."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    from finance_cli.core.native import java_executable
    env = {**os.environ, 'PATH': os.pathsep.join((str(Path(sys.executable).parent),
        str(Path(java_executable()).parent), os.environ.get('PATH', '')))}
    commands = [(name, [sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / directory)])
                for name, directory in [('shared', 'tests'), ('hometax', 'tests/hometax'), ('giro', 'tests/giro')]]
    commands.append(('hometax-node', ['node', '--test', *[str(p) for p in sorted((ROOT / 'tests/hometax').glob('*.test.mjs'))]]))
    reports = []
    for name, command in commands:
        start = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        log = result.stdout + result.stderr
        print(f'{name}: exit {result.returncode}, {time.monotonic()-start:.2f}s', flush=True)
        print(log[-3500:] if result.returncode else log[-500:], flush=True)
        reports.append({'suite': name, 'passed': result.returncode == 0, 'exit_code': result.returncode,
                        'seconds': round(time.monotonic()-start, 3), 'log': log})
    if '--report' in sys.argv:
        destination = Path(sys.argv[sys.argv.index('--report')+1])
        destination.write_text(json.dumps({'passed': all(r['passed'] for r in reports), 'suites': reports}, ensure_ascii=False, indent=2)+'\n')
    return 0 if all(r['passed'] for r in reports) else 1


if __name__ == '__main__':
    raise SystemExit(main())
