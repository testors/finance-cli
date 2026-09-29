#!/usr/bin/env python3
"""Verify installed commands and resources in a fresh environment."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SMOKE = r'''
import base64, contextlib, importlib, io, json, os, pkgutil, sys, tempfile
forbidden = json.loads(sys.argv[1])
def audit(event, args):
    if event.startswith('socket.connect') or event == 'socket.getaddrinfo':
        raise RuntimeError('offline distribution check forbids network')
    if event in ('open', 'os.listdir', 'os.scandir') and args and isinstance(args[0], (str, bytes)):
        value = os.fsdecode(args[0])
        if any(value == root or value.startswith(root + '/') for root in forbidden):
            raise RuntimeError('development checkout accessed: ' + event)
sys.addaudithook(audit)
for package in ('finance_cli', 'hometax_cli', 'giro'):
    module = importlib.import_module(package)
    for item in pkgutil.walk_packages(module.__path__, package + '.'):
        if not item.name.endswith('.__main__'):
            importlib.import_module(item.name)
from finance_cli.cli.main import main
rows = []
for args, source in (
    (['cert','list'], ''),
    (['capabilities'], ''),
    (['hana','encode-header'], '{"CHNL_SYS_HDPT":{"synthetic":true}}'),
    (['hana','session','list'], ''),
    (['hana','onesign','enroll','--name','synthetic','--run','plan'], ''),
    (['hana','transfer','execute','--name','synthetic','--session','s','--transaction','p','--run','plan'], ''),
    (['giro','request','national.list'], ''),
    (['giro','runtime','check'], ''),
    (['hometax','auth','replay','cert-register'], '{"RESULT":{"result":"S","msg":"synthetic"}}'),
):
    sys.stdin = io.StringIO(source)
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        code = main(args)
    if code != 0:
        raise RuntimeError('installed command failed: ' + repr(args))
    rows.append({'command':args,'result':json.loads(capture.getvalue())})
from PIL import Image
from hometax_cli.report_archive import archive_report
buffer = io.BytesIO()
Image.new('RGB', (1, 1)).save(buffer, format='PNG')
encoded = base64.b64encode(buffer.getvalue()).decode('ascii')
with tempfile.TemporaryDirectory() as destination:
    result = archive_report({'output': destination, 'expected_page_count': 1, 'pages': [{
        'svg': '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,'+encoded+'"/></svg>',
        'width': 2100, 'height': 2970}]})
    assert result['complete'] and result['image_count'] == 1
print(json.dumps({'commands':len(rows),'python_report_archive':True,'source_access':False,'network_used':False}))
'''


def run(command, *, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}): {command[0]}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    parser.add_argument('--node-runtime', action='store_true', help='Install pinned npm dependencies in the temporary home and verify installed JS assets')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    for required in ('giro/model_schema.json', 'hometax_cli/InvoiceSigner.java', 'hometax_cli/runtime/package-lock.json',
                     'hometax_cli/runtime_require.cjs', 'finance_cli/credentials/registry.py'):
        if required not in names:
            raise RuntimeError('missing package asset: ' + required)
    with tempfile.TemporaryDirectory(prefix='finance-distribution-') as temp:
        temporary = Path(temp).resolve()
        env = {k: v for k, v in os.environ.items() if k not in ('PYTHONPATH', 'PYTHONHOME', 'FINANCE_NODE_HOME')}
        env['FINANCE_HOME'] = str(temporary / 'user-data')
        run([sys.executable, '-m', 'venv', str(temporary / 'venv')], cwd=temporary, env=env)
        python = temporary / 'venv/bin/python'
        run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', str(wheel)], cwd=temporary, env=env)
        blocked = [str(ROOT)]
        report = json.loads(run([str(python), '-I', '-c', SMOKE, json.dumps(blocked)], cwd=temporary, env=env))
        report.update(wheel=wheel.name, package_files=len(names), isolated_install=True)
        if args.node_runtime:
            result = run([str(python), '-m', 'finance_cli', 'runtime', 'install', 'hometax'], cwd=temporary, env=env)
            installed = json.loads(result)
            package = run([str(python), '-I', '-c', 'import hometax_cli; from pathlib import Path; print(Path(hometax_cli.__file__).parent)'], cwd=temporary, env=env).strip()
            code = f"""import {{createRequire}} from 'node:module';
const require = createRequire(import.meta.url);
const dom = require({json.dumps(package + '/jsdom_compat.cjs')});
const {{archiveReport}} = await import({json.dumps(Path(package + '/report.mjs').as_uri())});
const result = archiveReport({{output:{json.dumps(str(temporary))},expected_page_count:1,
  pages:[{{svg:'<svg xmlns="http://www.w3.org/2000/svg"><text>synthetic</text></svg>',width:2100,height:2970}}]}});
if (!result.complete || !dom.JSDOM) throw new Error('installed runtime failed');
console.log(JSON.stringify({{dom:true,python_report_archive:true}}));
"""
            script = temporary / 'node-smoke.mjs'; script.write_text(code)
            env['FINANCE_NODE_HOME'] = installed['runtime_directory']
            env['FINANCE_PYTHON'] = str(python)
            report['node_runtime'] = json.loads(run(['node', str(script)], cwd=temporary, env=env))
            report['dependency_downloads'] = True
        report['passed'] = True
        if args.report:
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
