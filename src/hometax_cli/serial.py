"""Institution-wide serial execution for Hometax, shared by CLI, web and agents.

One Hometax login moves between the personal taxpayer and businesses inside
the service session, so target selection and the business request run under
one lock. It never waits: the CLI fails at once, the web queue tries later.
"""
from finance_cli.core import storage
from finance_cli.core.paths import data_home


def lock_path():
    home = storage.directory(data_home())
    return storage.directory(home / 'hometax') / 'operation.lock'


def operation():
    return storage.lock(lock_path())
