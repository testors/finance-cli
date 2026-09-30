"""OneSign store passphrases kept in the server process's memory only.

Chosen operation: the user unlocks a store once (web or ``fin server start
--unlock``) and the running server supplies the passphrase to OneSign jobs,
including transfers, until it stops or the store is locked again. Nothing is
written to disk, SQLite or logs; a worker still receives it only after it
holds the store's lock, through the same channel as any other step secret.
"""
import threading

from finance_cli.core import storage


def verify(name, passphrase):
    """Open the sealed state without taking its lock; raises on a wrong passphrase."""
    from finance_cli.services.hana import onesign_bundle as bundle, store
    from finance_cli.services.hana.onesign_keys import open_sealed
    from finance_cli.services.hana.onesign_state import FORMAT
    if not isinstance(passphrase, str) or not passphrase or len(passphrase) > 1024:
        raise ValueError('store_authentication_failed')
    path = store.root('identities') / store.name(name) / 'state.json'
    try:
        outer = storage.read_json(path)
    except OSError:
        raise ValueError('onesign_identity_not_found') from None
    if not isinstance(outer, dict) or set(outer) != {'format', 'salt', 'sealed'} or outer['format'] != FORMAT:
        raise ValueError('unsupported_onesign_state')
    salt = bundle.unb64url(outer['salt'])
    open_sealed(bundle.key(passphrase, salt), outer['sealed'], FORMAT.encode() + salt)


class Vaults:
    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def unlock(self, name, passphrase):
        verify(name, passphrase)
        with self._lock:
            self._items[name] = passphrase

    def lock(self, name):
        with self._lock:
            self._items.pop(name, None)

    def get(self, name):
        with self._lock:
            return self._items.get(name)

    def unlocked(self, name):
        return self.get(name) is not None
