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
    (['idcard','list'], ''),
    (['capabilities'], ''),
    (['hana','encode-header'], '{"CHNL_SYS_HDPT":{"synthetic":true}}'),
    (['hana','session','list'], ''),
    (['hana','corporate','login','--session','synthetic','--credential','synthetic'], ''),
    (['--format','json-v1','hana','corporate','login-onesign','--session','synthetic','--name','synthetic'], ''),
    (['hana','corporate','login-idpw','--user-id','SyntheticId'], ''),
    (['--format','json-v1','hana','corporate','login-idpw','--user-id','SyntheticId'], ''),
    (['hana','corporate','accounts'], ''),
    (['--format','json-v1','hana','corporate','history','--account','000101'], ''),
    (['hana','corporate','transfer','prepare','--from-account','000101','--to-bank','081','--to-account','000201','--amount','1000'], ''),
    (['hana','corporate','transfer','execute'], ''),
    (['hana','corporate','transfer','result'], ''),
    (['hana','corporate','transfer','cancel'], ''),
    (['hana','onesign','enroll','--name','synthetic','--run','plan'], ''),
    (['hana','transfer','execute','--name','synthetic','--session','s','--transaction','p','--run','plan'], ''),
    (['giro','request','national.list'], ''),
    (['giro','runtime','check'], ''),
    (['giro','auth','login'], ''),
    (['giro','auth','register'], ''),
    (['giro','bills','list','--type','national'], ''),
    (['giro','payment','pay'], ''),
    (['giro','receipts','list','--start-date','2026-10-01','--end-date','2026-10-03'], ''),
    (['hometax','auth','replay','cert-register'], '{"RESULT":{"result":"S","msg":"synthetic"}}'),
    (['--format','json-v1','hana','session','list'], ''),
    (['--format','json-v1','giro','auth','bootstrap'], ''),
    (['--format','json-v1','hometax','auth','replay','cert-login'], '{}'),
    (['server','status'], ''),
):
    sys.stdin = io.StringIO(source)
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        code = main(args)
    if code != 0:
        raise RuntimeError('installed command failed: ' + repr(args))
    result = json.loads(capture.getvalue())
    if args[:2] == ['--format', 'json-v1']:
        assert result['schema_version'] == 1 and result['exit_code'] == code
        assert result['service'] == args[2] and 'result' in result
    rows.append({'command':args,'result':result})
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
import asyncio
from finance_cli.server.app import create_app
from finance_cli.server.config import Config
app = create_app(Config(), dispatcher=False)
async def request(path, method='GET'):
    # One in-process ASGI request: no socket is opened.
    messages = []
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': method, 'scheme': 'http',
             'path': path, 'raw_path': path.encode(), 'query_string': b'', 'root_path': '',
             'headers': [(b'host', b'127.0.0.1:8740')], 'client': ('127.0.0.1', 50000), 'server': ('127.0.0.1', 8740)}
    async def receive():
        return {'type': 'http.request', 'body': b'', 'more_body': False}
    async def send(message):
        messages.append(message)
    await app(scope, receive, send)
    return messages[0]['status'], b''.join(m.get('body', b'') for m in messages[1:])
web = {}
for path in ('/', '/static/app.js', '/static/views.js', '/static/certificates.js', '/static/corporate.js', '/static/giro.js', '/static/app.css', '/api/v1/auth/state', '/api/v1/capabilities'):
    status, body = asyncio.run(request(path))
    web[path] = status
    assert body, path
assert web == {'/': 200, '/static/app.js': 200, '/static/views.js': 200, '/static/certificates.js': 200, '/static/corporate.js': 200, '/static/giro.js': 200, '/static/app.css': 200,
               '/api/v1/auth/state': 200, '/api/v1/capabilities': 401}, web
print(json.dumps({'commands':len(rows),'python_report_archive':True,'web_app':web,'source_access':False,'network_used':False}))
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
                     'hometax_cli/runtime_require.cjs', 'finance_cli/credentials/registry.py',
                     'finance_cli/server/static/index.html', 'finance_cli/server/static/app.js',
                     'finance_cli/server/static/app.css', 'finance_cli/server/Caddyfile.example',
                     'finance_cli/services/hana_corporate/cli.py'):
        if required not in names:
            raise RuntimeError('missing package asset: ' + required)
    with tempfile.TemporaryDirectory(prefix='finance-distribution-') as temp:
        temporary = Path(temp).resolve()
        env = {k: v for k, v in os.environ.items() if k not in ('PYTHONPATH', 'PYTHONHOME', 'FINANCE_NODE_HOME')}
        env['FINANCE_HOME'] = str(temporary / 'user-data')
        run([sys.executable, '-m', 'venv', str(temporary / 'venv')], cwd=temporary, env=env)
        python = temporary / 'venv/bin/python'
        run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', str(wheel) + '[web]'], cwd=temporary, env=env)
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
