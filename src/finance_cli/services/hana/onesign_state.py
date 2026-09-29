"""Passphrase-encrypted OneSign state and request receipts, with an outer lock."""
from contextlib import contextmanager
import copy
import secrets

from finance_cli.core import storage
from . import onesign_bundle as bundle, store
from .onesign_codec import encode, decode
from .onesign_keys import seal, open_sealed

FORMAT = 'finance-hana-state-v1'


class State:
    def __init__(self, name, password, initial=None):
        self.directory = store.root('identities') / store.name(name)
        self.path = self.directory / 'state.json'
        self.password = password
        self.initial = initial

    def __enter__(self):
        if self.initial is not None:
            if len(self.password) < 12:
                raise ValueError('passphrase_minimum_12_characters')
            for parent in (self.directory.parents[2],self.directory.parents[1],self.directory.parent):
                storage.directory(parent)
            self.directory.mkdir(mode=0o700)
        else:
            storage.no_symlinks(self.directory)
            if not self.directory.is_dir():
                raise ValueError('onesign_identity_not_found')
            storage.directory(self.directory)
        self.lock = storage.lock(self.directory / 'operation.lock')
        self.lock.__enter__()
        try:
            if self.initial is not None:
                self.salt = secrets.token_bytes(16)
                self.key = bundle.key(self.password, self.salt)
                self._write(self.initial)
            else:
                outer = storage.read_json(self.path)
                if set(outer) != {'format','salt','sealed'} or outer['format'] != FORMAT:
                    raise ValueError('unsupported_onesign_state')
                self.salt = bundle.unb64url(outer['salt'])
                if len(self.salt) != 16:
                    raise ValueError('invalid_onesign_state_salt')
                self.key = bundle.key(self.password, self.salt)
                self.snapshot()
            return self
        except BaseException:
            self.lock.__exit__(None, None, None)
            raise
        finally:
            self.password = None

    def __exit__(self, *args):
        self.key = None
        return self.lock.__exit__(*args)

    def snapshot(self):
        outer = storage.read_json(self.path)
        return decode(open_sealed(self.key, outer['sealed'], FORMAT.encode()+self.salt))

    def _write(self, value):
        storage.atomic_json(self.path, {'format': FORMAT, 'salt': bundle.b64url(self.salt),
            'sealed': seal(self.key, encode(value), FORMAT.encode()+self.salt)})

    @contextmanager
    def transaction(self):
        value = self.snapshot()
        yield value
        self._write(value)

    def record(self, run, name, value):
        directory = self.directory / 'runs' / store.name(run)
        storage.directory(directory)
        aad = (FORMAT+'/'+run+'/'+name).encode()+self.salt
        storage.write_new(directory / (store.name(name)+'.json'), encode({'sealed': seal(self.key, encode(value), aad)}))

    def read_record(self, run, name):
        path = self.directory / 'runs' / store.name(run) / (store.name(name)+'.json')
        aad = (FORMAT+'/'+run+'/'+name).encode()+self.salt
        return decode(open_sealed(self.key, storage.read_json(path)['sealed'], aad))

    def begin_run(self, run, operation):
        store.name(run)
        directory = self.directory / 'runs' / run
        storage.directory(directory.parent)
        # This on-disk reservation survives a failed state update.
        directory.mkdir(mode=0o700)
        with self.transaction() as state:
            if run in state['runs']:
                raise ValueError('run_already_attempted')
            state['runs'][run] = {'operation': operation, 'operations': {}, 'halted': False,
                                  'outcome': 'pending'}
        return Scope(self, ('runs', run))


class Scope:
    def __init__(self, state, path):
        self.state, self.path = state, path

    def snapshot(self):
        value = self.state.snapshot()
        for part in self.path:
            value = value[part]
        return copy.deepcopy(value)

    @contextmanager
    def transaction(self):
        with self.state.transaction() as value:
            for part in self.path:
                value = value[part]
            yield value
