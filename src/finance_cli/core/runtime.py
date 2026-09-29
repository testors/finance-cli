"""Explicit installation of the pinned Hometax Node runtime."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .paths import data_home, runtime_home
from . import storage


def node_environment():
    return {**os.environ, 'FINANCE_NODE_HOME': str(runtime_home()), 'FINANCE_PYTHON': sys.executable}


def status():
    home = runtime_home()
    return {'node': shutil.which('node'), 'npm': shutil.which('npm'),
            'runtime_directory': str(home),
            'installed': (home / 'node_modules/jsdom/package.json').is_file(),
            'required_jsdom': '30.1.1', 'network_used': False}


def install():
    import hometax_cli
    source = Path(hometax_cli.__file__).parent / 'runtime'
    storage.directory(data_home())
    storage.directory(data_home() / 'runtimes')
    home = storage.directory(runtime_home())
    npm = shutil.which('npm')
    if npm is None:
        raise ValueError('npm_required')
    with storage.lock(home / 'install.lock'):
        for filename in ('package.json', 'package-lock.json'):
            storage.atomic_json(home / filename, json.loads((source / filename).read_text()))
        result = subprocess.run([npm, 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
                                cwd=home, stdout=sys.stderr, check=False)
        if result.returncode:
            raise ValueError('node_runtime_install_failed')
    return {**status(), 'network_used': True}
