"""User state is independent of source checkouts and installed packages."""
import os
from pathlib import Path
import sys


def data_home():
    override = os.environ.get('FINANCE_HOME')
    if override:
        return Path(override).expanduser().absolute()
    if sys.platform == 'darwin':
        return Path.home() / 'Library/Application Support/finance-cli'
    if sys.platform == 'win32':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local')) / 'finance-cli'
    return Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share')) / 'finance-cli'


def runtime_home():
    return data_home() / 'runtimes/hometax'
